use chrono::DateTime;
use chrono::Utc;
use url::Url;

use std::borrow::Cow;

type Time = DateTime<Utc>;

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

pub struct Grant<'a> {
    pub owner_id: Cow<'a, str>,
    pub client_id: Cow<'a, str>,
    pub redirect_url: Cow<'a, Url>,
    pub scope: Cow<'a, Scope>,
    pub until: Cow<'a, Time>,
}

#[derive(Clone, Debug)]
pub struct IssuedToken {
    pub token: String,
    pub refresh: String,
    pub until: Time,
}

pub enum RegistrarError {
    Unregistered,
    MismatchedRedirect,
    Error(error::AuthorizationError),
}

/// Registrars provie a way to interact with clients.
///
/// Most importantly, they determine defaulted parameters for a request as well as the validity
/// of provided parameters. In general, implementations of this trait will probably offer an
/// interface for registering new clients. This interface is not covered by this library.
pub trait Registrar {
    /// Determine the allowed scope and redirection url for the client. The registrar may override
    /// the scope entirely or simply substitute a default scope in case none is given. Redirection
    /// urls should be matched verbatim, not partially.
    fn negotiate<'a>(&self, NegotiationParameter<'a>) -> Result<Cow<'a, Scope>, RegistrarError>;
}

/// Authorizers create and manage authorization codes.
///
/// The authorization code can be traded for a bearer token at the token endpoint.
pub trait Authorizer {
    /// Create a code which allows retrieval of a bearer token at a later time.
    fn authorize(&mut self, Request) -> String;
    /// Retrieve the parameters associated with a token, invalidating the code in the process. In
    /// particular, a code should not be usable twice (there is no stateless implementation of an
    /// authorizer for this reason).
    fn extract<'a>(&mut self, &'a str) -> Option<Grant<'a>>;
}

/// Issuers create bearer tokens.
///
/// It's the issuers decision whether a refresh token is offered or not. In any case, it is also
/// responsible for determining the validity and parameters of any possible token string. Some
/// backends or frontends may decide not to propagate the refresh token (for example because
/// they do not intend to offer a statefull refresh api).
pub trait Issuer {
    /// Create a token authorizing the request parameters
    fn issue(&mut self, Request) -> IssuedToken;
    /// Get the values corresponding to a bearer token
    fn recover_token<'a>(&'a self, &'a str) -> Option<Grant<'a>>;
    /// Get the values corresponding to a refresh token
    fn recover_refresh<'a>(&'a self, &'a str) -> Option<Grant<'a>>;
}

/// Generic token for a specific grant.
///
/// The interface may be reused for authentication codes, bearer tokens and refresh tokens.
pub trait TokenGenerator {
    /// For example sign a grant or generate a random token. The exact guarantees and uses depend
    /// on the specific implementation.
    fn generate(&self, &Grant) -> String;
}

pub mod authorizer;
pub mod backend;
pub mod error;
pub mod frontend;
pub mod generator;
pub mod issuer;
pub mod registrar;
mod scope;

#[cfg(test)]
mod tests;

pub use self::scope::Scope;

pub mod prelude {
    pub use super::authorizer::Storage;
    pub use super::backend::{CodeRef, IssuerRef, GuardRef};
    pub use super::issuer::{TokenMap, TokenSigner};
    pub use super::generator::RandomGenerator;
    pub use super::registrar::ClientMap;
    pub use super::scope::Scope;
}
