//! Adaptations and integration for Poem.
#![warn(missing_docs)]
#![deny(clippy::pedantic)]
// i hate this lint in particular
#![allow(clippy::module_name_repetitions)]

/// Things related to Requests (from the client)
pub mod request;
/// Errors for this crate.
pub mod error;
/// Things related to Responses (from the server)
pub mod response;
