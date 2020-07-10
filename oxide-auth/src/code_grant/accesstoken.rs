//! Provides the handling for Access Token Requests
use std::mem;
use std::borrow::Cow;
use std::collections::HashMap;

use chrono::{Duration, Utc};
use serde_json;

use code_grant::error::{AccessTokenError, AccessTokenErrorType};
use primitives::authorizer::Authorizer;
use primitives::issuer::{IssuedToken, Issuer};
use primitives::grant::{Extensions, Grant};
use primitives::registrar::{Registrar, RegistrarError};

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

pub struct AccessToken {
    state: AccessTokenState,
}

enum AccessTokenState {
    /// State after the request has been validated.
    Authenticate {
        client: String,
        passdata: Option<Vec<u8>>,
        code: String,
        // TODO: parsing here is unnecessary if we compare a string representation.
        redirect_uri: url::Url,
    },
    Recover {
        code: String,
        redirect_uri: url::Url,
    },
    Extend {
        saved_params: Grant,
        extensions: Extensions,
    },
    Issue {
        grant: Grant,
    },
    Err(Error),
}

pub enum Input<'req> {
    Request(&'req dyn Request),
    Authenticated,
    Recovered(Option<Grant>),
    Done,
    Issued(IssuedToken),
    None,
}

pub enum Output<'machine> {
    Authenticate {
        client: &'machine str,
        passdata: Option<&'machine [u8]>,
    },
    Recover {
        code: &'machine str,
    },
    Extend {
        grant: &'machine Grant,
        extensions: &'machine mut Extensions,
    },
    Issue {
        grant: &'machine Grant,
    },
    Ok(BearerToken),
    Err(Error),
}

impl AccessToken {
    pub fn new(request: &dyn Request) -> Self {
        AccessToken {
            state: Self::validate(request).unwrap_or_else(AccessTokenState::Err),
        }
    }

    pub fn advance(&mut self, input: Input) -> Output<'_> {
        self.state = match (self.take(), input) {
            (current, Input::None) => current,
            (
                AccessTokenState::Authenticate {
                    code, redirect_uri, ..
                },
                Input::Authenticated,
            ) => Self::authencicated(code, redirect_uri),
            (AccessTokenState::Recover { code, redirect_uri }, Input::Recovered(grant)) => {
                Self::recovered(code, redirect_uri, grant).unwrap_or_else(AccessTokenState::Err)
            }
            (
                AccessTokenState::Extend {
                    saved_params,
                    extensions,
                },
                Input::Done,
            ) => Self::issue(saved_params, extensions),
            (AccessTokenState::Issue { grant }, Input::Issued(token)) => {
                return Output::Ok(Self::finish(grant, token));
            }
            (AccessTokenState::Err(err), _) => AccessTokenState::Err(err),
            (_, _) => AccessTokenState::Err(Error::Primitive(PrimitiveError::empty())),
        };

        self.output()
    }

    fn output(&mut self) -> Output<'_> {
        match &mut self.state {
            AccessTokenState::Err(err) => Output::Err(err.clone()),
            AccessTokenState::Authenticate { client, passdata, .. } => Output::Authenticate {
                client,
                passdata: passdata.as_ref().map(Vec::as_slice),
            },
            AccessTokenState::Recover { code, .. } => Output::Recover { code },
            AccessTokenState::Extend {
                saved_params,
                extensions,
            } => Output::Extend {
                grant: saved_params,
                extensions,
            },
            AccessTokenState::Issue { grant } => Output::Issue { grant },
        }
    }

    fn take(&mut self) -> AccessTokenState {
        mem::replace(
            &mut self.state,
            AccessTokenState::Err(Error::Primitive(PrimitiveError::empty())),
        )
    }

    fn validate(request: &dyn Request) -> Result<AccessTokenState> {
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

        let (client_id, passdata) = credentials.into_client().ok_or_else(Error::invalid)?;

        let redirect_uri = request
            .redirect_uri()
            .ok_or_else(Error::invalid)?
            .parse()
            .map_err(|_| Error::invalid())?;

        let code = request.code().ok_or_else(Error::invalid)?;

        Ok(AccessTokenState::Authenticate {
            client: client_id.to_string(),
            passdata: passdata.map(Vec::from),
            redirect_uri: redirect_uri,
            code: code.into_owned(),
        })
    }

    fn authencicated(code: String, redirect_uri: url::Url) -> AccessTokenState {
        AccessTokenState::Recover { code, redirect_uri }
    }

    fn recovered(
        client_id: String, redirect_uri: url::Url, grant: Option<Grant>,
    ) -> Result<AccessTokenState> {
        let mut saved_params = match grant {
            None => return Err(Error::invalid()),
            Some(v) => v,
        };

        if (saved_params.client_id.as_str(), &saved_params.redirect_uri) != (&client_id, &redirect_uri) {
            return Err(Error::invalid_with(AccessTokenErrorType::InvalidGrant));
        }

        if saved_params.until < Utc::now() {
            return Err(Error::invalid_with(AccessTokenErrorType::InvalidGrant));
        }

        let extensions = mem::replace(&mut saved_params.extensions, Extensions::default());
        Ok(AccessTokenState::Extend {
            saved_params,
            extensions,
        })
    }

    fn issue(grant: Grant, extensions: Extensions) -> AccessTokenState {
        AccessTokenState::Issue {
            grant: Grant { extensions, ..grant },
        }
    }

    fn finish(grant: Grant, token: IssuedToken) -> BearerToken {
        BearerToken(token, grant.scope.to_string())
    }
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
#[derive(Clone)]
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
#[derive(Clone)]
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
#[derive(Clone)]
pub struct ErrorDescription {
    error: AccessTokenError,
}

type Result<T> = std::result::Result<T, Error>;

/// Represents an access token, a refresh token and the associated scope for serialization.
pub struct BearerToken(IssuedToken, String);

impl Error {
    pub fn invalid() -> Self {
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

    pub fn unauthorized(authtype: &str) -> Error {
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

impl PrimitiveError {
    fn empty() -> Self {
        PrimitiveError {
            grant: None,
            extensions: None,
        }
    }
}

impl ErrorDescription {
    /// Convert the error into a json string, viable for being sent over a network with
    /// `application/json` encoding.
    pub fn to_json(self) -> String {
        let asmap = self
            .error
            .into_iter()
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
    pub fn to_json(self) -> String {
        #[derive(Serialize)]
        struct Serial<'a> {
            access_token: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            refresh_token: Option<&'a str>,
            token_type: &'a str,
            expires_in: String,
            scope: &'a str,
        }

        let remaining = self.0.until.signed_duration_since(Utc::now());
        let serial = Serial {
            access_token: self.0.token.as_str(),
            refresh_token: Some(self.0.refresh.as_str()).filter(|_| self.0.refreshable()),
            token_type: "bearer",
            expires_in: remaining.num_seconds().to_string(),
            scope: self.1.as_str(),
        };

        serde_json::to_string(&serial).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn bearer_token_encoding() {
        let token = BearerToken(
            IssuedToken {
                token: "access".into(),
                refresh: "refresh".into(),
                until: Utc::now(),
            },
            "scope".into(),
        );

        let json = token.to_json();
        let mut token = serde_json::from_str::<HashMap<String, String>>(&json).unwrap();

        assert_eq!(token.remove("access_token"), Some("access".to_string()));
        assert_eq!(token.remove("refresh_token"), Some("refresh".to_string()));
        assert_eq!(token.remove("scope"), Some("scope".to_string()));
        assert_eq!(token.remove("token_type"), Some("bearer".to_string()));
        assert!(token.remove("expires_in").is_some());
    }

    #[test]
    fn no_refresh_encoding() {
        let token = BearerToken(
            IssuedToken::without_refresh("access".into(), Utc::now()),
            "scope".into(),
        );

        let json = token.to_json();
        let mut token = serde_json::from_str::<HashMap<String, String>>(&json).unwrap();

        assert_eq!(token.remove("access_token"), Some("access".to_string()));
        assert_eq!(token.remove("refresh_token"), None);
        assert_eq!(token.remove("scope"), Some("scope".to_string()));
        assert_eq!(token.remove("token_type"), Some("bearer".to_string()));
        assert!(token.remove("expires_in").is_some());
    }
}
