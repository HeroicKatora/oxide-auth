//! oxide-auth
//! ==============
//! A OAuth2 server library, for use in combination with iron or other frontends, featuring a set of
//! configurable and pluggable backends.
//!
//! About
//! --------------
//! `oxide-auth` aims at providing a comprehensive and extensible interface to managing oauth2
//! tokens on a server. While the core package is agnostic of the used frontend, an optional iron
//! adaptor is provided with the default configuration. Through an interface designed with traits,
//! the frontend is as easily pluggable as the backend.
//!
//! By default, the `iron` frontend is included in a module of the same name while testing is done
//! internally with an offline frontend. The interface those two methods use is exactly the same,
//! guaranteeing responses to be the same in both cases.
//!
//! Custom Frontends
//! -------
//! A key feature is the ability to add your own frontend without jeopardizing safety requirements.
//! This requires custom, related implementations of [`WebRequest`] and [`WebResponse`].
//! _WARNING_: Custom frontends MUST ensure a secure communication layer with confidential clients.
//! This means using TLS for communication over http (although there are currently discussions to
//! consider communication to `localhost` as always occuring in a secure context).
//!
//! For more information, see the documentation of [`frontend`]
//!
//! [`WebRequest`]: code_grant/frontend/trait.WebRequest.html
//! [`WebResponse`]: code_grant/frontend/trait.WebResponse.html
//! [`frontend`]: code_grant/frontend/index.html
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

pub mod code_grant;
#[cfg(feature = "iron-backend")]
pub mod iron;
pub mod primitives;
