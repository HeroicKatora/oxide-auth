//! A collection of primites useful for more than one authorization method.
//!
//! There only is, as you might have noticed, only the code grant method. But abstracting away the
//! underlying primitives provides an incentive to –e.g.– provide a database based implementation
//! independently of a particular web server library (*wink*).

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
    pub use super::generator::{TokenGenerator, RandomGenerator};
    pub use super::registrar::{Registrar, Client, ClientUrl, ClientMap, PreGrant};
    pub use super::scope::Scope;
}
