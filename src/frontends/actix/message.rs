use super::actix::prelude::Message;

use super::resolve::{ResolvedRequest, ResolvedResponse};
use code_grant::frontend::{OAuthError, OwnerAuthorization, PreGrant};

pub type BoxedOwner = Box<(Fn(&PreGrant) -> OwnerAuthorization<ResolvedResponse>) + Send + Sync>;
pub struct AuthorizationCode {
    pub(super) request: ResolvedRequest,
    pub(super) owner: BoxedOwner,
}
pub struct AccessToken(pub(super) ResolvedRequest);
pub struct Guard(pub(super) ResolvedRequest);

impl Message for AuthorizationCode {
    type Result = Result<ResolvedResponse, OAuthError>;
}

impl Message for AccessToken {
    type Result = Result<ResolvedResponse, OAuthError>;
}

impl Message for Guard {
    type Result = Result<(), OAuthError>;
}
