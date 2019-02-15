//! A baseline implemention of [`Endpoint`] and [`WebRequest`].
//!
//! Contains primitive extension implementations as well as straightforward request formats
//! suitable for HTTP-less OAuth applications. This is useful for testing as well as token
//! endpoints that operate behind an HTTP portal, or even for applying OAuth2 outside the web
//! domain.
//!
//! [`Endpoint`]: ../../endpoint/trait.Endpoint.html
//! [`WebRequest`]: ../../endpoint/trait.Endpoint.html
pub mod endpoint;

pub mod extensions;

pub mod request;

