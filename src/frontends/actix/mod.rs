//! Bindings and utilities for creating an oauth endpoint with actix.
extern crate actix;
extern crate actix_web;
extern crate futures;

use self::actix_web::HttpRequest;

mod endpoint;
pub mod message;
mod resolve;
pub mod request;

use self::request::{AuthorizationCode, AccessToken, Guard};

pub use self::endpoint::CodeGrantEndpoint;
pub use self::resolve::ResolvedResponse;
pub use code_grant::frontend::{AuthorizationFlow, GrantFlow, AccessFlow, PreGrant, OwnerAuthorization};

/// Bundles all oauth related methods under a single type.
pub trait OAuth {
    /// Convert an http request to an oauth request which provides all possible sub types.
    fn oauth2(self) -> OAuthRequest;
}

/// An encapsulated http request providing builder-style access to all oauth request types.
pub struct OAuthRequest(HttpRequest);

impl<State> OAuth for HttpRequest<State> {
    fn oauth2(self) -> OAuthRequest {
        OAuthRequest(self.drop_state())
    }
}

impl OAuthRequest {
    /// Build an authorization code request from the http request.
    ///
    /// The provided method `check` will be sent inside the request and MUST validate that the
    /// resource owner has approved the authorization grant that was requested.  This is
    /// application specific logic that MUST check that the validiting owner is authenticated.
    pub fn authorization_code<F>(self, check: F) -> AuthorizationCode
    where
        F: Fn(&PreGrant) -> OwnerAuthorization<ResolvedResponse>,
        F: Sync + Send + 'static
     {
        let OAuthRequest(request) = self;
        AuthorizationCode::new(request, Box::new(check))
    }

    /// Treat http request as a bearer token request.
    pub fn access_token(self) -> AccessToken {
        let OAuthRequest(request) = self;
        AccessToken::new(request)
    }

    /// Extract the bearer token from the request to guard a resource.
    pub fn guard(self) -> Guard {
        let OAuthRequest(request) = self;
        Guard::new(request)
    }
}
