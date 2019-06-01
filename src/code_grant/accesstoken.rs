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
}

/// A system of addons provided additional data.
///
/// An endpoint not having any extension may use `&mut ()` as the result of system.
pub trait Extension {
    /// Inspect the request and extension data to produce extension data.
    ///
    /// The input data comes from the extension data produced in the handling of the
    /// authorization code request.
    fn extend(&mut self, request: &Request, data: Extensions) -> std::result::Result<Extensions, ()>;
}

impl Extension for () {
    fn extend(&mut self, _: &Request, _: Extensions) -> std::result::Result<Extensions, ()> {
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
    fn registrar(&self) -> &Registrar;

    /// Get the authorizer from which we can recover the authorization.
    fn authorizer(&mut self) -> &mut Authorizer;

    /// Return the issuer instance to create the access token.
    fn issuer(&mut self) -> &mut Issuer;

    /// The system of used extension, extending responses.
    ///
    /// It is possible to use `&mut ()`.
    fn extension(&mut self) -> & mut Extension;
}

/// Try to redeem an authorization code.
pub fn access_token(handler: &mut Endpoint, request: &Request) -> Result<BearerToken> {
    if !request.valid() {
        return Err(Error::invalid())
    }

    let authorization = request.authorization();
    let client_id = request.client_id();
    let (client_id, auth): (&str, Option<&[u8]>) = match (&client_id, &authorization) {
        (&None, &Some((ref client_id, ref auth))) => (client_id.as_ref(), Some(auth.as_ref())),
        (&Some(ref client_id), &None) => (client_id.as_ref(), None),
        _ => return Err(Error::invalid()),
    };

    handler.registrar()
        .check(&client_id, auth)
        .map_err(|err| match err {
            RegistrarError::Unspecified => Error::unauthorized("basic"),
            RegistrarError::PrimitiveError => Error::Primitive(PrimitiveError {
                grant: None,
                extensions: None,
            }),
        })?;

    match request.grant_type() {
        Some(ref cow) if cow == "authorization_code" => (),
        None => return Err(Error::invalid()),
        Some(_) => return Err(Error::invalid_with(AccessTokenErrorType::UnsupportedGrantType)),
    };

    let code = request
        .code()
        .ok_or(Error::invalid())?;
    let code = code.as_ref();

    let saved_params = match handler.authorizer().extract(code) {
        Err(()) => return Err(Error::Primitive(PrimitiveError {
            grant: None,
            extensions: None,
        })),
        Ok(None) => return Err(Error::invalid()),
        Ok(Some(v)) => v,
    };

    let redirect_uri = request
        .redirect_uri()
        .ok_or(Error::invalid())?;
    let redirect_uri = redirect_uri
        .as_ref()
        .parse()
        .map_err(|_| Error::invalid())?;

    if (saved_params.client_id.as_ref(), &saved_params.redirect_uri) != (client_id, &redirect_uri) {
        return Err(Error::invalid_with(AccessTokenErrorType::InvalidGrant))
    }

    if saved_params.until < Utc::now() {
        return Err(Error::invalid_with(AccessTokenErrorType::InvalidGrant))
    }

    let code_extensions = saved_params.extensions;
    let access_extensions = handler.extension().extend(request, code_extensions);
    let access_extensions = match access_extensions {
        Ok(extensions) => extensions,
        Err(_) =>  return Err(Error::invalid()),
    };

    let token = handler.issuer().issue(Grant {
        client_id: saved_params.client_id,
        owner_id: saved_params.owner_id,
        redirect_uri: saved_params.redirect_uri,
        scope: saved_params.scope.clone(),
        until: Utc::now() + Duration::hours(1),
        extensions: access_extensions,
    }).map_err(|()| Error::Primitive(PrimitiveError {
        // FIXME: endpoint should get and handle these.
        grant: None,
        extensions: None,
    }))?;

    Ok(BearerToken{ 0: token, 1: saved_params.scope.to_string() })
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
            error: AccessTokenError::default()
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
        Error::Unauthorized(ErrorDescription {
                error: {
                    let mut error = AccessTokenError::default();
                    error.set_type(AccessTokenErrorType::InvalidClient);
                    error
                },
            },
            authtype.to_string())
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
    pub fn to_json(self) -> String {
        use std::iter::IntoIterator;
        use std::collections::HashMap;
        let asmap = self.error.into_iter()
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
    pub fn to_json(self) -> String {
        let remaining = self.0.until.signed_duration_since(Utc::now());
        let kvmap: HashMap<_, _> = vec![
            ("access_token", self.0.token),
            ("refresh_token", self.0.refresh),
            ("token_type", "bearer".to_string()),
            ("expires_in", remaining.num_seconds().to_string()),
            ("scope", self.1)].into_iter().collect();
        serde_json::to_string(&kvmap).unwrap()
    }
}
