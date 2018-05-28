extern crate actix;
extern crate actix_web;
extern crate futures;

use self::actix_web::{HttpMessage, HttpRequest};

mod message;
mod resolve;
mod request;

pub use self::request::{AuthorizationCode, AccessToken, Guard};

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
    pub fn authorization_code(self) -> AuthorizationCode {
        let OAuthRequest(request) = self;
        AuthorizationCode::new(request)
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
