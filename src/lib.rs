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
//! By default, the `iron` backend is included in a module of the same name while testing is done
//! internally without any network connections. The interface those two methods use is exactly the
//! same, guaranteeing responses to be the same in both cases.

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

#[warn(missing_docs)]
pub mod primitives;

#[cfg(feature = "iron-backend")]
#[warn(missing_docs)]
pub mod iron;

pub mod code_grant;
