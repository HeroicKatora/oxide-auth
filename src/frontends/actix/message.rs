use super::actix::dev::*;
use super::actix_web::dev::*;

use super::actix_web::{HttpMessage, HttpRequest, HttpResponse};
use super::resolve::ResolvedRequest;
use code_grant::frontend::OAuthError;

pub struct AuthorizationCode(pub(super) ResolvedRequest);
pub struct AccessToken(pub(super) ResolvedRequest);
pub struct Guard(pub(super) ResolvedRequest);

impl Message for AuthorizationCode {
    type Result = Result<HttpResponse, OAuthError>;
}

impl Message for AccessToken {
    type Result = Result<HttpResponse, OAuthError>;
}

impl Message for Guard {
    type Result = Result<(), OAuthError>;
}
