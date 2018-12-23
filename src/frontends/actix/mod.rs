//! Bindings and utilities for creating an oauth endpoint with actix.
extern crate actix;
extern crate actix_web;
extern crate futures;

use self::actix_web::HttpRequest;

// mod endpoint;
pub mod message;
pub mod request;

// pub use self::endpoint::CodeGrantEndpoint;
pub use self::request::OAuthFuture;
pub use self::request::OAuthRequest;
pub use code_grant::endpoint::{AuthorizationFlow, AccessTokenFlow, ResourceFlow, PreGrant, OwnerConsent, OwnerSolicitor};

/// Bundles all oauth related methods under a single type.
pub trait OAuth {
    /// Convert an http request to an oauth request which provides all possible sub types.
    fn oauth2(self) -> OAuthFuture;
}

impl<'a, State> OAuth for &'a HttpRequest<State> {
    fn oauth2(self) -> OAuthFuture {
        OAuthFuture::new(self)
    }
}

