//! Bindings and utilities for creating an oauth endpoint with actix.
//!
//! Use the provided methods to use code grant methods in an asynchronous fashion, or use an
//! `AsActor<_>` to create an actor implementing endpoint functionality via messages.
#![warn(missing_docs)]

mod future_endpoint;
mod endpoint;
pub mod message;
pub mod request;
#[cfg(test)]
mod tests;

use std::fmt;
use std::error;

use actix_web::{HttpRequest, HttpResponse};
use actix_web::ResponseError;

// pub use self::endpoint::CodeGrantEndpoint;
pub use oxide_auth::endpoint::{PreGrant, OAuthError, OwnerConsent, OwnerSolicitor};
pub use oxide_auth::primitives::grant::Grant;
pub use self::request::OAuthFuture;
pub use self::request::OAuthRequest;
pub use self::request::OAuthResponse;

pub use self::future_endpoint::{ResourceProtection, access_token, authorization, refresh, resource};

/// Bundles all oauth related methods under a single type.
pub trait OAuth {
    /// Convert an http request to an oauth request which provides all possible sub types.
    fn oauth2(self) -> OAuthFuture;
}

/// Newtype wrapper around a primitive, transforming it into an actor.
pub struct AsActor<P>(pub P);

/// Newtype struct wrapper around an error.
///
/// Implements the `actix_web::ResponseError` trait so it can be used as an error in a route.
#[derive(Debug)]
pub struct OAuthFailure(OAuthError);

impl<'a, State> OAuth for &'a HttpRequest<State> {
    fn oauth2(self) -> OAuthFuture {
        OAuthFuture::new(self)
    }
}

impl fmt::Display for OAuthFailure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<OAuthError> for OAuthFailure {
    fn from(err: OAuthError) -> Self {
        OAuthFailure(err)
    }
}

impl error::Error for OAuthFailure { }

impl ResponseError for OAuthFailure {
    fn error_response(&self) -> HttpResponse {
        match self.0 {
            OAuthError::DenySilently => HttpResponse::BadRequest().finish(),
            OAuthError::PrimitiveError => HttpResponse::InternalServerError().finish(),
            OAuthError::BadRequest => HttpResponse::BadRequest().finish(),
        }
    }
}
