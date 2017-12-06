//! A collection of primites useful for more than one authorization method.

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
use self::scope::Scope;

pub struct Request<'a> {
    pub owner_id: &'a str,
    pub client_id: &'a str,
    pub redirect_url: &'a Url,
    pub scope: &'a Scope,
}

pub mod prelude {
    pub use super::authorizer::{Authorizer, Storage};
    pub use super::issuer::{IssuedToken, Issuer, TokenMap, TokenSigner};
    pub use super::generator::{TokenGenerator, RandomGenerator};
    pub use super::registrar::{Registrar, Client, ClientParameter, ClientMap};
    pub use super::scope::Scope;
}
