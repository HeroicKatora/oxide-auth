//! Provides the handling for Access Token Requests
use std::borrow::Cow;
use std::collections::HashMap;

use chrono::{Duration, Utc};
use serde_json;

use code_grant::error::{AccessTokenError, AccessTokenErrorType};
use primitives::authorizer::Authorizer;
use primitives::issuer::{IssuedToken, Issuer};
use primitives::grant::{Extensions, Grant};
use primitives::registrar::{Registrar, RegistrarError};

/// Token Response
#[derive(Deserialize, Serialize)]
pub(crate) struct TokenResponse {
    /// The access token issued by the authorization server.
    #[serde(skip_serializing_if="Option::is_none")]
    pub access_token: Option<String>,

    /// The refresh token, which can be used to obtain new access tokens.
    #[serde(skip_serializing_if="Option::is_none")]
    pub refresh_token: Option<String>,

    /// The type of the token issued.
    #[serde(skip_serializing_if="Option::is_none")]
    pub token_type: Option<String>,

    /// The lifetime in seconds of the access token.
    #[serde(skip_serializing_if="Option::is_none")]
    pub expires_in: Option<i64>,

    /// The scope, which limits the permissions on the access token.
    #[serde(skip_serializing_if="Option::is_none")]
    pub scope: Option<String>,

    /// Error code
    #[serde(skip_serializing_if="Option::is_none")]
    pub error: Option<String>,
}

/// Trait based retrieval of parameters necessary for access token request handling.
pub trait Request {
    /// Received request might not be encoded correctly. This method gives implementors the chance
    /// to signal that a request was received but its encoding was generally malformed. If this is
    /// the case, then no other attribute will be queried. This method exists mainly to make
    /// frontends straightforward by not having them handle special cases for malformed requests.
    fn valid(&self) -> bool;

    /// The authorization code grant for which an access token is wanted.
    fn code(&self) -> Option<Cow<str>>;

    /// User:password of a basic authorization header.
    fn authorization(&self) -> Option<(Cow<str>, Cow<[u8]>)>;

    /// The client_id, optional parameter for public clients.
    fn client_id(&self) -> Option<Cow<str>>;

    /// Valid request have the redirect url used to request the authorization code grant.
    fn redirect_uri(&self) -> Option<Cow<str>>;

    /// Valid requests have this set to "authorization_code"
    fn grant_type(&self) -> Option<Cow<str>>;

    /// Retrieve an additional parameter used in an extension
    fn extension(&self, key: &str) -> Option<Cow<str>>;

    /// Credentials in body should only be enabled if use of HTTP Basic is not possible.
    ///
    /// Allows the request body to contain the `client_secret` as a form parameter. This is NOT
    /// RECOMMENDED and need not be supported. The parameters MUST NOT appear in the request URI
    /// itself.
    ///
    /// Under these considerations, support must be explicitely enabled.
    fn allow_credentials_in_body(&self) -> bool {
        false
    }
}

/// A system of addons provided additional data.
///
/// An endpoint not having any extension may use `&mut ()` as the result of system.
pub trait Extension {
    /// Inspect the request and extension data to produce extension data.
    ///
    /// The input data comes from the extension data produced in the handling of the
    /// authorization code request.
    fn extend(&mut self, request: &dyn Request, data: Extensions)
        -> std::result::Result<Extensions, ()>;
}

impl Extension for () {
    fn extend(&mut self, _: &dyn Request, _: Extensions) -> std::result::Result<Extensions, ()> {
        Ok(Extensions::new())
    }
}

/// Required functionality to respond to access token requests.
///
/// Each method will only be invoked exactly once when processing a correct and authorized request,
/// and potentially less than once when the request is faulty.  These methods should be implemented
/// by internally using `primitives`, as it is implemented in the `frontend` module.
pub trait Endpoint {
    /// Get the client corresponding to some id.
    fn registrar(&self) -> &dyn Registrar;

    /// Get the authorizer from which we can recover the authorization.
    fn authorizer(&mut self) -> &mut dyn Authorizer;

    /// Return the issuer instance to create the access token.
    fn issuer(&mut self) -> &mut dyn Issuer;

    /// The system of used extension, extending responses.
    ///
    /// It is possible to use `&mut ()`.
    fn extension(&mut self) -> &mut dyn Extension;
}

enum Credentials<'a> {
    /// No credentials were offered.
    None,
    /// One set of credentials was offered.
    Authenticated {
        client_id: &'a str,
        passphrase: &'a [u8],
    },
    /// No password but name was offered.
    ///
    /// This must happen only when the credentials were part of the request body but used to
    /// indicate the name of a public client.
    Unauthenticated { client_id: &'a str },
    /// Multiple possible credentials were offered.
    ///
    /// This is a security issue, only one attempt must be made per request.
    Duplicate,
}

/// Try to redeem an authorization code.
pub fn access_token(handler: &mut dyn Endpoint, request: &dyn Request) -> Result<BearerToken> {
    if !request.valid() {
        return Err(Error::invalid());
    }

    let authorization = request.authorization();
    let client_id = request.client_id();
    let client_secret = request.extension("client_secret");

    let mut credentials = Credentials::None;
    if let Some((client_id, auth)) = &authorization {
        credentials.authenticate(client_id.as_ref(), auth.as_ref());
    }

    if let Some(client_id) = &client_id {
        match &client_secret {
            Some(auth) if request.allow_credentials_in_body() => {
                credentials.authenticate(client_id.as_ref(), auth.as_ref().as_bytes())
            }
            // Ignore parameter if not allowed.
            Some(_) | None => credentials.unauthenticated(client_id.as_ref()),
        }
    }

    match request.grant_type() {
        Some(ref cow) if cow == "authorization_code" => (),
        None => return Err(Error::invalid()),
        Some(_) => return Err(Error::invalid_with(AccessTokenErrorType::UnsupportedGrantType)),
    };

    let (client_id, auth) = credentials.into_client().ok_or_else(Error::invalid)?;

    handler
        .registrar()
        .check(&client_id, auth)
        .map_err(|err| match err {
            RegistrarError::Unspecified => Error::unauthorized("basic"),
            RegistrarError::PrimitiveError => Error::Primitive(PrimitiveError {
                grant: None,
                extensions: None,
            }),
        })?;

    let code = request.code().ok_or_else(Error::invalid)?;
    let code = code.as_ref();

    let saved_params = match handler.authorizer().extract(code) {
        Err(()) => {
            return Err(Error::Primitive(PrimitiveError {
                grant: None,
                extensions: None,
            }))
        }
        Ok(None) => return Err(Error::invalid()),
        Ok(Some(v)) => v,
    };

    let redirect_uri = request.redirect_uri().ok_or_else(Error::invalid)?;
    let redirect_uri = redirect_uri.as_ref().parse().map_err(|_| Error::invalid())?;

    if (saved_params.client_id.as_ref(), &saved_params.redirect_uri) != (client_id, &redirect_uri) {
        return Err(Error::invalid_with(AccessTokenErrorType::InvalidGrant));
    }

    if saved_params.until < Utc::now() {
        return Err(Error::invalid_with(AccessTokenErrorType::InvalidGrant));
    }

    let code_extensions = saved_params.extensions;
    let access_extensions = handler.extension().extend(request, code_extensions);
    let access_extensions = match access_extensions {
        Ok(extensions) => extensions,
        Err(_) => return Err(Error::invalid()),
    };

    let token = handler
        .issuer()
        .issue(Grant {
            client_id: saved_params.client_id,
            owner_id: saved_params.owner_id,
            redirect_uri: saved_params.redirect_uri,
            scope: saved_params.scope.clone(),
            until: Utc::now() + Duration::hours(1),
            extensions: access_extensions,
        })
        .map_err(|()| {
            Error::Primitive(PrimitiveError {
                // FIXME: endpoint should get and handle these.
                grant: None,
                extensions: None,
            })
        })?;

    Ok(BearerToken {
        0: token,
        1: saved_params.scope.to_string(),
    })
}

impl<'a> Credentials<'a> {
    pub fn authenticate(&mut self, client_id: &'a str, passphrase: &'a [u8]) {
        self.add(Credentials::Authenticated {
            client_id,
            passphrase,
        })
    }

    pub fn unauthenticated(&mut self, client_id: &'a str) {
        self.add(Credentials::Unauthenticated { client_id })
    }

    pub fn into_client(self) -> Option<(&'a str, Option<&'a [u8]>)> {
        match self {
            Credentials::Authenticated {
                client_id,
                passphrase,
            } => Some((client_id, Some(passphrase))),
            Credentials::Unauthenticated { client_id } => Some((client_id, None)),
            _ => None,
        }
    }

    fn add(&mut self, new: Self) {
        use std::mem::replace;
        let old = replace(self, Credentials::None);
        let next = match old {
            Credentials::None => new,
            _ => Credentials::Duplicate,
        };
        replace(self, next);
    }
}

/// Defines actions for the response to an access token request.
pub enum Error {
    /// The token did not represent a valid token.
    Invalid(ErrorDescription),

    /// The client did not properly authorize itself.
    Unauthorized(ErrorDescription, String),

    /// An underlying primitive operation did not complete successfully.
    ///
    /// This is expected to occur with some endpoints. See `PrimitiveError` for
    /// more details on when this is returned.
    Primitive(PrimitiveError),
}

/// The endpoint should have enough control over its primitives to find
/// out what has gone wrong, e.g. they may externall supply error
/// information.
///
/// In this case, all previous results returned by the primitives are
/// included in the return value. Through this mechanism, one can
/// accomodate async handlers by implementing a sync-based result cache
/// that is filled with these partial values. In case only parts of the
/// outstanding futures, invoked during internal calls, are ready the
/// cache can be refilled through the error eliminating polls to already
/// sucessful futures.
///
/// Note that `token` is not included in this list, since the handler
/// can never fail after supplying a token to the backend.
pub struct PrimitiveError {
    /// The already extracted grant.
    ///
    /// You may reuse this, or more precisely you must to fulfill this exact request in case of
    /// an error recovery attempt.
    pub grant: Option<Grant>,

    /// The extensions that were computed.
    pub extensions: Option<Extensions>,
}

/// Simple wrapper around AccessTokenError to imbue the type with addtional json functionality. In
/// addition this enforces backend specific behaviour for obtaining or handling the access error.
pub struct ErrorDescription {
    error: AccessTokenError,
}

type Result<T> = std::result::Result<T, Error>;

/// Represents an access token, a refresh token and the associated scope for serialization.
pub struct BearerToken(IssuedToken, String);

impl Error {
    fn invalid() -> Self {
        Error::Invalid(ErrorDescription {
            error: AccessTokenError::default(),
        })
    }

    fn invalid_with(with_type: AccessTokenErrorType) -> Self {
        Error::Invalid(ErrorDescription {
            error: {
                let mut error = AccessTokenError::default();
                error.set_type(with_type);
                error
            },
        })
    }

    fn unauthorized(authtype: &str) -> Error {
        Error::Unauthorized(
            ErrorDescription {
                error: {
                    let mut error = AccessTokenError::default();
                    error.set_type(AccessTokenErrorType::InvalidClient);
                    error
                },
            },
            authtype.to_string(),
        )
    }

    /// Get a handle to the description the client will receive.
    ///
    /// Some types of this error don't return any description which is represented by a `None`
    /// result.
    pub fn description(&mut self) -> Option<&mut AccessTokenError> {
        match self {
            Error::Invalid(description) => Some(description.description()),
            Error::Unauthorized(description, _) => Some(description.description()),
            Error::Primitive(_) => None,
        }
    }
}

impl ErrorDescription {
    /// Convert the error into a json string, viable for being sent over a network with
    /// `application/json` encoding.
    pub fn to_json(&self) -> String {
        let asmap = self.error
            .iter()
            .map(|(k, v)| (k.to_string(), v.into_owned()))
            .collect::<HashMap<String, String>>();
        serde_json::to_string(&asmap).unwrap()
    }

    /// Get a handle to the description the client will receive.
    pub fn description(&mut self) -> &mut AccessTokenError {
        &mut self.error
    }
}

impl BearerToken {
    /// Convert the token into a json string, viable for being sent over a network with
    /// `application/json` encoding.
    // FIXME: rename to `into_json` or have `&self` argument.
    pub fn to_json(&self) -> String {
        let remaining = self.0.until.signed_duration_since(Utc::now());
        let token_response = TokenResponse {
            access_token: Some(self.0.token.clone()),
            refresh_token: self.0.refresh.clone(),
            token_type: Some("bearer".to_owned()),
            expires_in: Some(remaining.num_seconds()),
            scope: Some(self.1.clone()),
            error: None,
        };

        serde_json::to_string(&token_response).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_token_encoding() {
        let token = BearerToken(IssuedToken {
            token: "access".into(),
            refresh: Some("refresh".into()),
            until: Utc::now(),
        }, "scope".into());

        let json = token.to_json();
        let token = serde_json::from_str::<TokenResponse>(&json).unwrap();

        assert_eq!(token.access_token, Some("access".to_owned()));
        assert_eq!(token.refresh_token, Some("refresh".to_owned()));
        assert_eq!(token.scope, Some("scope".to_owned()));
        assert_eq!(token.token_type, Some("bearer".to_owned()));
        assert!(token.expires_in.is_some());
    }

    #[test]
    fn no_refresh_encoding() {
        let token = BearerToken(
            IssuedToken::without_refresh("access".into(), Utc::now()),
            "scope".into(),
        );

        let json = token.to_json();
        let token = serde_json::from_str::<TokenResponse>(&json).unwrap();

        assert_eq!(token.access_token, Some("access".to_owned()));
        assert_eq!(token.refresh_token, None);
        assert_eq!(token.scope, Some("scope".to_owned()));
        assert_eq!(token.token_type, Some("bearer".to_owned()));
        assert!(token.expires_in.is_some());
    }
}
