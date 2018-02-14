//! Fully implemented frontends.
//!
//! Frontends are glue adapters from other http server crates to internal

#[cfg(feature = "iron-frontend")]
pub mod iron;
#[cfg(feature = "rouille-frontend")]
pub mod rouille;
