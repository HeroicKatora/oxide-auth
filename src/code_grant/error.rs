use std::fmt;
use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::vec::IntoIter;
use url::Url;

#[derive(Debug)]
pub enum AuthorizationErrorType {
    /// The request is missing a required parameter, includes an invalid parameter value, includes
    /// a parameter more than once, or is otherwise malformed.
    InvalidRequest,

    /// The client is not authorized to request an authorization code using this method.
    UnauthorizedClient,

    /// The resource owner or authorization server denied the request.
    AccessDenied,

    /// The authorization server does not support obtaining an authorization code using this method.
    UnsupportedResponseType,

    /// The requested scope is invalid, unknown, or malformed.
    InvalidScope,

    /// The authorization server encountered an unexpected condition that prevented it from
    /// fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP
    /// status code cannot be returned to the client via an HTTP redirect.)
    ServerError,

    /// The authorization server is currently unable to handle the request due to a temporary
    /// overloading or maintenance of the server.  (This error code is needed because a 503 Service
    /// Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)
    TemporarilyUnavailable,
}

impl AuthorizationErrorType {
    fn description(&self) -> &'static str {
        match *self {
            AuthorizationErrorType::InvalidRequest => "invalid_request",
            AuthorizationErrorType::UnauthorizedClient => "unauthorized_client",
            AuthorizationErrorType::AccessDenied => "access_denied",
            AuthorizationErrorType::UnsupportedResponseType => "unsupported_response_type",
            AuthorizationErrorType::InvalidScope => "invalid_scope",
            AuthorizationErrorType::ServerError => "server_error",
            AuthorizationErrorType::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

impl AsRef<str> for AuthorizationErrorType {
    fn as_ref(&self) -> &str {
        self.description()
    }
}

impl fmt::Display for AuthorizationErrorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

pub trait AuthorizationErrorExt {
    fn modify(self, &mut AuthorizationError);
}

/// Represents parameters of an error in an [Authorization Error Response](Authorization Error)
/// [Authorization Error]: https://tools.ietf.org/html/rfc6749#section-4.2.2.1
pub struct AuthorizationError {
    error: AuthorizationErrorType,
    description: Option<Cow<'static, str>>,
    uri: Option<Cow<'static, str>>,
}

impl AuthorizationError {
    pub fn with<A: AuthorizationErrorExt>(modifier: A) -> AuthorizationError {
        let mut error = AuthorizationError {
            error: AuthorizationErrorType::InvalidRequest,
            description: None,
            uri: None,
        };
        modifier.modify(&mut error);
        error
    }
}

/* Error modifiers, changing or adding attributes if in proper format */

impl AuthorizationErrorExt for () {
    fn modify(self, _error: &mut AuthorizationError) { }
}

impl AuthorizationErrorExt for AuthorizationError {
    fn modify(self, error: &mut AuthorizationError) {
        error.error = self.error;
        error.description = self.description;
        error.uri = self.uri;
    }
}

impl AuthorizationErrorExt for &'static str {
    fn modify(self, error: &mut AuthorizationError) {
        error.description = Some(Cow::Borrowed(self));
    }
}

impl AuthorizationErrorExt for Url {
    fn modify(self, error: &mut AuthorizationError) {
        error.uri = Some(Cow::Owned(self.as_str().to_string()))
    }
}

impl AuthorizationErrorExt for AuthorizationErrorType {
    fn modify(self, error: &mut AuthorizationError) {
        error.error = self;
    }
}

impl<A> AuthorizationErrorExt for Cell<A> where A: Sized + AuthorizationErrorExt {
    fn modify(self, error: &mut AuthorizationError) {
        self.into_inner().modify(error)
    }
}

impl<A> AuthorizationErrorExt for RefCell<A> where A: Sized + AuthorizationErrorExt {
    fn modify(self, error: &mut AuthorizationError) {
        self.into_inner().modify(error)
    }
}

impl<A, B> AuthorizationErrorExt for (A, B) where A: AuthorizationErrorExt, B: AuthorizationErrorExt {
    fn modify(self, error: &mut AuthorizationError) {
        self.0.modify(error);
        self.1.modify(error);
    }
}

/* Error encodings, e.g. url and json */

impl IntoIterator for AuthorizationError {
    type Item = (&'static str, Cow<'static, str>);
    type IntoIter = IntoIter<(&'static str, Cow<'static, str>)>;
    fn into_iter(self) -> Self::IntoIter {
        let mut vec = vec![("error", Cow::Borrowed(self.error.description()))];
        self.description.map(|d| vec.push(("description", d)));
        self.uri.map(|uri| vec.push(("uri", uri)));
        vec.into_iter()
    }
}

//////////////////////////////////////////////////////////////////////////////////
//                             Access Request Error                             //
// detailed in https://tools.ietf.org/html/rfc6749#section-5.2                  //
//////////////////////////////////////////////////////////////////////////////////

/// All defined error codes
#[derive(Debug)]
pub enum AccessTokenErrorType {
    /// The request is missing a required parameter, includes an unsupported parameter value (other
    // than grant type), repeats a parameter, includes multiple credentials, utilizes more than one
    /// mechanism for authenticating the client, or is otherwise malformed.
    InvalidRequest,

    /// Client authentication failed (e.g., unknown client, no client authentication included, or
    /// unsupported authentication method).  The authorization server MAY return an HTTP 401
    /// (Unauthorized) status code to indicate which HTTP authentication schemes are supported.
    /// If the client attempted to authenticate via the "Authorization" request header field, the
    /// authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include
    /// the "WWW-Authenticate" response header field matching the authentication scheme used by the
    /// client.
    InvalidClient,

    /// The provided authorization grant (e.g., authorization code, resource owner credentials) or
    /// refresh token is invalid, expired, revoked, does not match the redirection URI used in the
    /// authorization request, or was issued to another client.
    InvalidGrant,

    /// The authenticated client is not authorized to use this authorization grant type.
    UnauthorizedClient,

    /// The authorization grant type is not supported by the authorization server.
    UnsupportedGrantType,

    /// The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the
    /// resource owner.
    InvalidScope,
}

impl AccessTokenErrorType {
    fn description(&self) -> &'static str {
        match *self {
            AccessTokenErrorType::InvalidRequest => "invalid_request",
            AccessTokenErrorType::InvalidClient => "invalid_client",
            AccessTokenErrorType::InvalidGrant => "invalid_grant",
            AccessTokenErrorType::UnauthorizedClient => "unauthorized_client",
            AccessTokenErrorType::UnsupportedGrantType => "unsupported_grant_type",
            AccessTokenErrorType::InvalidScope => "invalid_scope",
        }
    }
}

impl AsRef<str> for AccessTokenErrorType {
    fn as_ref(&self) -> &str {
        self.description()
    }
}

impl fmt::Display for AccessTokenErrorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

pub trait AccessTokenErrorExt {
    fn modify(self, &mut AccessTokenError);
}

/// Represents parameters of an error in an [Issuing Error Response](Issuing Error)
/// [ISsuing Error]: https://tools.ietf.org/html/rfc6749#section-5.2
pub struct AccessTokenError {
    error: AccessTokenErrorType,
    description: Option<Cow<'static, str>>,
    uri: Option<Cow<'static, str>>,
}

impl AccessTokenError {
    pub fn with<A: AccessTokenErrorExt>(modifier: A) -> AccessTokenError {
        let mut error = AccessTokenError {
            error: AccessTokenErrorType::InvalidRequest,
            description: None,
            uri: None,
        };
        modifier.modify(&mut error);
        error
    }
}

/* Error modifiers, changing or adding attributes if in proper format */

impl AccessTokenErrorExt for () {
    fn modify(self, _error: &mut AccessTokenError) { }
}

impl AccessTokenErrorExt for AccessTokenError {
    fn modify(self, error: &mut AccessTokenError) {
        error.error = self.error;
        error.description = self.description;
        error.uri = self.uri;
    }
}

impl AccessTokenErrorExt for &'static str {
    fn modify(self, error: &mut AccessTokenError) {
        error.description = Some(Cow::Borrowed(self));
    }
}

impl AccessTokenErrorExt for Url {
    fn modify(self, error: &mut AccessTokenError) {
        error.uri = Some(Cow::Owned(self.as_str().to_string()))
    }
}

impl AccessTokenErrorExt for AccessTokenErrorType {
    fn modify(self, error: &mut AccessTokenError) {
        error.error = self;
    }
}

impl<A> AccessTokenErrorExt for Cell<A> where A: Sized + AccessTokenErrorExt {
    fn modify(self, error: &mut AccessTokenError) {
        self.into_inner().modify(error)
    }
}

impl<A> AccessTokenErrorExt for RefCell<A> where A: Sized + AccessTokenErrorExt {
    fn modify(self, error: &mut AccessTokenError) {
        self.into_inner().modify(error)
    }
}

impl<A, B> AccessTokenErrorExt for (A, B) where A: AccessTokenErrorExt, B: AccessTokenErrorExt {
    fn modify(self, error: &mut AccessTokenError) {
        self.0.modify(error);
        self.1.modify(error);
    }
}

/* Error encodings, e.g. url and json */

impl IntoIterator for AccessTokenError {
    type Item = (&'static str, Cow<'static, str>);
    type IntoIter = IntoIter<(&'static str, Cow<'static, str>)>;
    fn into_iter(self) -> Self::IntoIter {
        let mut vec = vec![("error", Cow::Borrowed(self.error.description()))];
        self.description.map(|d| vec.push(("description", d)));
        self.uri.map(|uri| vec.push(("uri", uri)));
        vec.into_iter()
    }
}
