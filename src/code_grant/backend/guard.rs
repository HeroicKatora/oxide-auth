use std::borrow::Cow;

use chrono::Utc;

use primitives::grant::Grant;
use primitives::scope::Scope;

/// Indicates the reason for access failure.
pub enum AccessError {
    /// The request did not have enough authorization data or was otherwise malformed.
    InvalidRequest,

    /// The provided authorization did not grant sufficient priviledges.
    AccessDenied,
}

type AccessResult<T> = Result<T, AccessError>;

/// Required request methods for deciding on the rights to access a protected resource.
pub trait GuardRequest {
    /// Received request might not be encoded correctly. This method gives implementors the chance
    /// to signal that a request was received but its encoding was generally malformed. If this is
    /// the case, then no other attribute will be queried. This method exists mainly to make
    /// frontends straightforward by not having them handle special cases for malformed requests.
    fn valid(&self) -> bool;
    /// The authorization used in the request.
    ///
    /// Expects the complete `Authorization` HTTP-header, including the qualification as `Bearer`.
    /// In case the client included multiple forms of authorization, this method MUST return None
    /// and the request SHOULD be marked as invalid.
    fn token(&self) -> Option<Cow<str>>;
}

pub trait GuardEndpoint {
    fn scopes(&self) -> &[Scope];

    fn recover_token(&self, &str) -> Option<Grant>;
}

/// The result will indicate whether the resource access should be allowed or not.
pub fn protect(handler: &GuardEndpoint, req: &GuardRequest)
-> AccessResult<()> {
    if !req.valid() {
        return Err(AccessError::InvalidRequest)
    }

    let token = req.token()
        .ok_or(AccessError::AccessDenied)?;
    let grant = handler.recover_token(&token)
        .ok_or(AccessError::AccessDenied)?;

    if grant.until < Utc::now() {
        return Err(AccessError::AccessDenied);
    }

    // Test if any of the possible allowed scopes is included in the grant
    if !handler.scopes().iter()
        .any(|resource_scope| resource_scope.allow_access(&grant.scope)) {
        return Err(AccessError::AccessDenied);
    }

    return Ok(())
}
