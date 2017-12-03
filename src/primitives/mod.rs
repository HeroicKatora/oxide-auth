use chrono::DateTime;
use chrono::Utc;
use url::Url;

use std::borrow::Cow;

pub mod authorizer;
pub mod generator;
pub mod grant;
pub mod issuer;
pub mod registrar;
pub mod scope;

type Time = DateTime<Utc>;
use self::scope::Scope;

pub struct NegotiationParameter<'a> {
    pub client_id: Cow<'a, str>,
    pub redirect_url: Cow<'a, Url>,
    pub scope: Option<Cow<'a, Scope>>,
}

pub struct Negotiated<'a> {
    pub client_id: Cow<'a, str>,
    pub scope: Cow<'a, Scope>,
    pub redirect_url: Url,
}

pub struct Request<'a> {
    pub owner_id: &'a str,
    pub client_id: &'a str,
    pub redirect_url: &'a Url,
    pub scope: &'a Scope,
}

#[derive(Clone, Debug)]
pub struct IssuedToken {
    pub token: String,
    pub refresh: String,
    pub until: Time,
}

pub mod prelude {
    pub use super::authorizer::{Authorizer, Storage};
    pub use super::issuer::{Issuer, TokenMap, TokenSigner};
    pub use super::generator::{TokenGenerator, RandomGenerator};
    pub use super::registrar::{Registrar, ClientMap};
    pub use super::scope::Scope;
}
