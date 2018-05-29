use super::actix::prelude::Message;

use super::resolve::{ResolvedRequest, ResolvedResponse};
use code_grant::frontend::OAuthError;

pub struct AuthorizationCode(pub(super) ResolvedRequest);
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
