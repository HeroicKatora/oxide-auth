use std::fmt;
use std::borrow::Cow;
use std::cell::{Cell, RefCell};
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

impl fmt::Display for AuthorizationErrorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match self {
            &AuthorizationErrorType::InvalidRequest => "invalid_request",
            &AuthorizationErrorType::UnauthorizedClient => "unauthorized_client",
            &AuthorizationErrorType::AccessDenied => "access_denied",
            &AuthorizationErrorType::UnsupportedResponseType => "unsupported_response_type",
            &AuthorizationErrorType::InvalidScope => "invalid_scope",
            &AuthorizationErrorType::ServerError => "server_error",
            &AuthorizationErrorType::TemporarilyUnavailable => "temporarily_unavailable",
        })
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

pub trait ErrorEncoder {
    fn encode(&mut self, AuthorizationError);
}
