//! A collection of primites useful for more than one authorization method.
//!
//! A primitive is the smallest independent unit of policy used in OAuth related endpoints. For
//! example, an `authorizer` generates and verifies Authorization Codes.  There only is, as you
//! might have noticed, only the OAuth2 code grant method. But abstracting away the underlying
//! primitives makes it possible to provide –e.g.– a independent database based implementation.
//!
//! These should be used to build or instantiate an `Endpoint`, for example [`Generic`] or your
//! own.
//!
//! ```
//! # extern crate oxide_auth;
//! # extern crate oxide_auth_ring;
//! # use oxide_auth::frontends::simple::endpoint::Vacant;
//! use oxide_auth::frontends::simple::endpoint::Generic;
//! use oxide_auth::primitives::{
//!     authorizer::AuthMap,
//!     generator::RandGenerator,
//!     issuer::TokenMap,
//!     registrar::ClientMap,
//! };
//! use oxide_auth_ring::registrar::Pbkdf2;
//!
//! Generic {
//!     authorizer: AuthMap::new(RandGenerator::new(16)),
//!     registrar: ClientMap::new(Pbkdf2::default()),
//!     issuer: TokenMap::new(RandGenerator::new(16)),
//!     // ...
//! #   scopes: Vacant,
//! #   solicitor: Vacant,
//! #   response: Vacant,
//! };
//! ```
//!
//! [`Generic`]: ../frontends/simple/endpoint/struct.Generic.html

use chrono::DateTime;
use chrono::Utc;
use url::Url;

pub mod authorizer;
pub mod generator;
pub mod grant;
pub mod issuer;
pub mod registrar;
pub mod scope;

type Time = DateTime<Utc>;

/// Commonly used primitives for frontends and backends.
pub mod prelude {
    pub use super::authorizer::{Authorizer, AuthMap};
    pub use super::issuer::{IssuedToken, Issuer, TokenMap, TokenSigner};
    pub use super::generator::TagGrant;
    pub use super::registrar::{Registrar, Client, ClientUrl, ClientMap, PreGrant};
    pub use super::scope::Scope;
}
