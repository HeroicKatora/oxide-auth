use crate::OAuthRequest;
use axum::{
    http::{header::InvalidHeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use oxide_auth::frontends::{dev::OAuthError, simple::endpoint::Error};

#[derive(Debug)]
/// The error type for Oxide Auth operations
pub enum WebError {
    /// Errors occurring in Endpoint operations
    Endpoint(OAuthError),

    /// Errors occurring in Endpoint operations
    Header(InvalidHeaderValue),

    /// Errors with the request encoding
    Encoding,

    /// Request body could not be parsed as a form
    Form,

    /// Request query was absent or could not be parsed
    Query,

    /// Request query was absent or could not be parsed
    Body,

    /// The Authorization header was invalid
    Authorization,

    /// General internal server error
    InternalError(Option<String>),
}

impl std::fmt::Display for WebError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            WebError::Endpoint(ref e) => write!(f, "Endpoint, {}", e),
            WebError::Header(ref e) => write!(f, "Couldn't set header, {}", e),
            WebError::Encoding => write!(f, "Error decoding request"),
            WebError::Form => write!(f, "Request is not a form"),
            WebError::Query => write!(f, "No query present"),
            WebError::Body => write!(f, "No body present"),
            WebError::Authorization => write!(f, "Request has invalid Authorization headers"),
            WebError::InternalError(None) => write!(f, "An internal server error occurred"),
            WebError::InternalError(Some(ref e)) => {
                write!(f, "An internal server error occurred: {}", e)
            }
        }
    }
}

impl std::error::Error for WebError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            WebError::Endpoint(ref e) => e.source(),
            WebError::Header(ref e) => e.source(),
            _ => None,
        }
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
    }
}

impl From<Error<OAuthRequest>> for WebError {
    fn from(e: Error<OAuthRequest>) -> Self {
        match e {
            Error::Web(e) => e,
            Error::OAuth(e) => e.into(),
        }
    }
}

impl From<OAuthError> for WebError {
    fn from(e: OAuthError) -> Self {
        WebError::Endpoint(e)
    }
}

impl From<InvalidHeaderValue> for WebError {
    fn from(e: InvalidHeaderValue) -> Self {
        Self::Header(e)
    }
}
