use std::error;
use std::fmt;

use code_grant_2::guard::Error as ResourceError;
use super::WebResponse;

/// Errors which should not or need not be communicated to the requesting party but which are of
/// interest to the server. See the documentation for each enum variant for more documentation on
/// each as some may have an expected response. These include badly formatted headers or url encoded
/// body, unexpected parameters, or security relevant required parameters.
#[derive(Debug)]
pub enum OAuthError {
    /// Deny authorization to the client by essentially dropping the request.
    ///
    /// For example, this response is given when an incorrect client has been provided in the
    /// authorization request in order to avoid potential indirect denial of service vulnerabilities.
    DenySilently,

    /// One of the primitives used to complete the operation failed.
    PrimitiveError,

    /// The incoming request was malformed.
    ///
    /// This implies that it did not change any internal state.
    InvalidRequest,
}

impl OAuthError {
    /// Create a response for the request that produced this error.
    ///
    /// After inspecting the error returned from the library API and doing any necessary logging,
    /// this methods allows easily turning the error into a template (or complete) response to the
    /// client.  It takes care of setting the necessary headers.
    pub fn response_or<W: WebResponse>(self, internal_error: W) -> W {
        match self {
            OAuthError::DenySilently | OAuthError::InvalidRequest => W::text("")
                .and_then(|response| response.as_client_error()),
            OAuthError::PrimitiveError => return internal_error,
        }.unwrap_or(internal_error)
    }

    /// Create a response for the request that produced this error.
    ///
    /// After inspecting the error returned from the library API and doing any necessary logging,
    /// this methods allows easily turning the error into a template (or complete) response to the
    /// client.  It takes care of setting the necessary headers.
    pub fn response_or_else<W, F>(self, internal_error: F) -> W
        where F: FnOnce() -> W, W: WebResponse
    {
        match self {
            OAuthError::DenySilently | OAuthError::InvalidRequest => W::text("")
                .and_then(|response| response.as_client_error()),
            OAuthError::PrimitiveError => return internal_error(),
        }.unwrap_or_else(|_| internal_error())
    }
}

impl fmt::Display for OAuthError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        fmt.write_str("OAuthError")
    }
}

impl error::Error for OAuthError {
    fn description(&self) -> &str {
        "OAuthError"
    }
}
