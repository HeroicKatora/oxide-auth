use std::fmt;
use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::vec::IntoIter;
use url::Url;

#[derive(Debug)]
pub enum AuthorizationErrorType {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
}

impl AuthorizationErrorType {
    fn description(&self) -> &'static str {
        match self {
            &AuthorizationErrorType::InvalidRequest => "invalid_request",
            &AuthorizationErrorType::UnauthorizedClient => "unauthorized_client",
            &AuthorizationErrorType::AccessDenied => "access_denied",
            &AuthorizationErrorType::UnsupportedResponseType => "unsupported_response_type",
            &AuthorizationErrorType::InvalidScope => "invalid_scope",
            &AuthorizationErrorType::ServerError => "server_error",
            &AuthorizationErrorType::TemporarilyUnavailable => "temporarily_unavailable",
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
