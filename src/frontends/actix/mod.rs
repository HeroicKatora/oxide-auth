extern crate actix;
extern crate actix_web;
extern crate futures;

use self::actix_web::HttpRequest;

mod endpoint;
mod message;
mod resolve;
mod request;

pub use self::endpoint::CodeGrantEndpoint;
pub use self::request::{AuthorizationCode, AccessToken, Guard};
pub use self::resolve::ResolvedResponse;
pub use code_grant::frontend::{AuthorizationFlow, GrantFlow, AccessFlow, PreGrant, OwnerAuthorization};

/// Bundles all oauth related methods under a single type.
pub trait OAuth {
    fn oauth2(self) -> OAuthRequest;
}

pub struct OAuthRequest(HttpRequest);

impl<State> OAuth for HttpRequest<State> {
    fn oauth2(self) -> OAuthRequest {
        OAuthRequest(self.drop_state())
    }
}

impl OAuthRequest {
    pub fn authorization_code<F>(self, f: F) -> AuthorizationCode
    where
        F: Fn(&PreGrant) -> OwnerAuthorization<ResolvedResponse>,
        F: Sync + Send + 'static
     {
        let OAuthRequest(request) = self;
        AuthorizationCode::new(request, Box::new(f))
    }

    pub fn access_token(self) -> AccessToken {
        let OAuthRequest(request) = self;
        AccessToken::new(request)
    }

    pub fn guard(self) -> Guard {
        let OAuthRequest(request) = self;
        Guard::new(request)
    }
}
