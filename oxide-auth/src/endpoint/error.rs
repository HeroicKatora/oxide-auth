use std::error;
use std::fmt;

/// Errors which should not or need not be communicated to the requesting party but which are of
/// interest to the server. See the documentation for each enum variant for more documentation on
/// each as some may have an expected response. These include badly formatted headers or url encoded
/// body, unexpected parameters, or security relevant required parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OAuthError {
    /// Deny authorization to the client by essentially dropping the request.
    ///
    /// For example, this response is given when an incorrect client has been provided in the
    /// authorization request in order to avoid potential indirect denial of service vulnerabilities.
    DenySilently,

    /// One of the primitives used to complete the operation failed.
    ///
    /// This indicates a problem in the server configuration or the frontend library or the
    /// implementation of the primitive underlying those two.
    PrimitiveError,

    /// The incoming request was malformed.
    ///
    /// This implies that it did not change any internal state. Note that this differs from an
    /// `InvalidRequest` as in the OAuth specification. `BadRequest` is reported by a frontend
    /// implementation of a request, due to http non-compliance, while an `InvalidRequest` is a
    /// type of response to an authorization request by a user-agent that is sent to the specified
    /// client (although it may be caused by a bad request).
    BadRequest,
}

impl fmt::Display for OAuthError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            OAuthError::DenySilently => fmt.write_str("OAuthError: Request should be silently denied"),
            OAuthError::PrimitiveError => fmt.write_str("OAuthError: Server component failed"),
            OAuthError::BadRequest => fmt.write_str("OAuthError: Bad request"),
        }
    }
}

impl error::Error for OAuthError {}
