//! Adaptations and integration for Axum.
#![warn(missing_docs)]

mod error;
pub use error::WebError;

mod request;
pub use request::{OAuthResource, OAuthRequest};

mod response;
pub use response::OAuthResponse;
