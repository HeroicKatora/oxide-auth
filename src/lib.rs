//! # oxide-auth
//!
//! A OAuth2 server library, for use in combination with actix-web or other frontends, featuring a
//! set of configurable and pluggable backends.
//!
//! ## About
//!
//! `oxide-auth` aims at providing a comprehensive and extensible interface to managing oauth2
//! tokens on a server. While the core package is agnostic of the used frontend, an optional actix
//! adaptor is provided with the default configuration. Through an interface designed with traits,
//! the frontend is as easily pluggable as the backend.
//!
//! The `actix` frontend, included as a default feature, provides bindings to create an endpoint in
//! `actix-web`.
//!
//! ## Example
//!
//! A fully featured [web server example][actix example] is realized with actix.
//!
//! > `$ cargo run --example actix`
//!
//! # Use cases
//!
//! Versatility is a primary goal.  Consequently, there are several different scenarios in which
//! this library will be useful.  Of course all of them are related to server side use of OAuth2
//! protocol.
//!
//! ## Create a web server with OAuth security
//!
//! So you want to build a new OAuth provider? Instead of only relying on tokens provided by other
//! large internet entities, you want to make your own tokens? This library and OAuth2 was built to
//! safely provide authorization tokens to third-party clients, distinct from your users that
//! authorize them. Examples of this use case: A web facing data portal, automation endpoints (in
//! the style of Reddit or Discord), or even to restrict the authorization of different components
//! of your own software by applying these techniques to your `REST` backend.
//!
//! This library can be integrated into several different web server libraries.  Most prominently
//! `actix-web`, `rocket` and `iron`.  These frontends allow you to easily answer OAuth requests and
//! secure protected resources, utilizing the library provided http request types.  Some provide
//! additional abstractions for an integrated feeling.
//!
//! A complete list can be found in the [`frontends`] module.
//!
//! You can also use this library with any HTTP frontend, see [`frontends::simple`].
//!
//! ## Custom Frontends
//!
//! A key feature is the ability to add your own frontend without jeopardizing safety requirements.
//! For example to add your in-house `REST` library! This requires custom, related implementations
//! of [`WebRequest`] and [`WebResponse`]. _WARNING_: Custom frontends MUST ensure a secure
//! communication layer with confidential clients. This means using TLS for communication over
//! https.
//!
//! For more information, see the documentation of [`endpoint`] and [`frontends`].
//!
//! ## Using the primitives
//!
//! All [`primitives`] can be used independently of the frontend modules.  This makes them reusable
//! for other authentication methods.  But this works the other way around as well.  Your own
//! implementations of these primitives can be used directly in conjuction with all frontends
//! (although some may impose `Send` or `Sync` constraits due to limitations of the web library).
//!
//! [`WebRequest`]: code_grant/frontend/trait.WebRequest.html
//! [`WebResponse`]: code_grant/frontend/trait.WebResponse.html
//! [`endpoint`]: endpoint/index.html
//! [`frontends`]: frontends/index.html
//! [`frontends::simple`]: frontends/simple/index.html
//! [`primitives`]: primitives/index.html
//! [actix example]: examples/actix.rs
//!
#![warn(missing_docs)]

extern crate base64;
extern crate chrono;
extern crate url;
extern crate ring;
extern crate rmp_serde;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

pub mod code_grant;
pub mod endpoint;
pub mod frontends;
pub mod primitives;
