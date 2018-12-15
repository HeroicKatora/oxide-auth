//! # oxide-auth
//!
//! A OAuth2 server library, for use in combination with iron or other frontends, featuring a set of
//! configurable and pluggable backends.
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
//! A fully featured [example][actix example] is realized with actix.
//!
//!
//! > `$ cargo run --example authorization_actix`
//!
//! # Use cases
//!
//! Versatility is a primary goal.  Consequently, there are sever different scenarios in which
//! this library will be useful.  Of course all of them are related to server side use of OAuth2
//! protocol.
//!
//! ## Create a web server with OAuth security
//!
//! This library can be integrated into several different web server libraries.  Most prominently
//! `actix-web` and `gotham`.  These frontends allow you to easily answer OAuth requests and
//! secure protected resources, utilizing the library provided http request types.  Some provide
//! additional abstractions for an integrated feeling.
//!
//! A complete list can be found in the [`frontends`] module.
//!
//! ## Using the primitives
//!
//! All [`primitives`] can be used independently of the frontend modules.  This makes them reusable
//! for other authentication methods.  But this works the other way around as well.  Your own
//! implementations of these primitives can be used directly in conjuction with all frontends
//! (although some may impose `Send` or `Sync` constraits due to limitations of the web library).
//!
//! ## Custom Frontends
//!
//! A key feature is the ability to add your own frontend without jeopardizing safety requirements.
//! This requires custom, related implementations of [`WebRequest`] and [`WebResponse`].
//! _WARNING_: Custom frontends MUST ensure a secure communication layer with confidential clients.
//! This means using TLS for communication over http (although there are currently discussions to
//! consider communication to `localhost` as always occuring in a secure context).
//!
//! For more information, see the documentation of [`code_grant::frontend`]
//!
//! [`WebRequest`]: code_grant/frontend/trait.WebRequest.html
//! [`WebResponse`]: code_grant/frontend/trait.WebResponse.html
//! [`code_grant::frontend`]: code_grant/frontend/index.html
//! [`frontends`]: frontends/index.html
//! [`primitives`]: primitives/index.html
//! [actix example]: examples/authorization_code.rs
#![warn(missing_docs)]

extern crate base64;
extern crate chrono;
extern crate url;
extern crate rand;
extern crate ring;
extern crate rmp_serde;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

// These are top level because gotham derive expects them to be.
#[cfg(feature = "gotham-frontend")]
extern crate gotham;
#[cfg(feature = "gotham-frontend")]
#[macro_use]
extern crate gotham_derive;

pub mod code_grant;
pub mod frontends;
pub mod primitives;
