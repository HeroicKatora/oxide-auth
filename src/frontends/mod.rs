//! Fully implemented frontends.
//!
//! Frontends are glue adapters from other http server crates to the interface exposed by
//! individual methods offered in this crate. The exact usage of the frontend varies from
//! implementation to implementation. Composability and usability are the main concerns for
//! frontends, full feature support is a secondary concern.
//!
//! Guide
//! ------
//!
//! All frontend implementations should start with two closely related traits: [`WebRequest`] and
//! [`WebResponse`].  These central interfaces are used to interact with the libraries supported
//! token flows (currently only authorization code grant).
//!
//! Lets step through those implementations one by one.
//!

#[cfg(feature = "actix-frontend")]
pub mod actix;
#[cfg(feature = "iron-frontend")]
pub mod iron;
#[cfg(feature = "rouille-frontend")]
pub mod rouille;
