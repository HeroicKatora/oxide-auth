//! Provides actix message encapsulations.
//!
//! The http types, especially `HttpRequest` can not be shared across threads.  Therefore,
//! the relevant information is extracted into special message types first.
mod authorizer;
mod issuer;
mod registrar;

use super::actix::prelude::Message;

use super::request::{OAuthRequest as ResolvedRequest};
use code_grant::endpoint::{OAuthError, OwnerConsent, PreGrant, WebRequest};

pub use self::authorizer::{Authorize, Extract};
pub use self::issuer::{Issue, RecoverToken, RecoverRefresh};
pub use self::registrar::{BoundRedirect, Check, Negotiate};

/// Approves or denies are grant request based on owner information.
///
/// This is basically and sendable version of the much more generic `OwnerAuthorizer` concept
/// found in the basic code grant frontend.  All necessary data for validation needs to be
/// owned (and `Sync`) because the request struct of `actix_web` can not be sent between all
/// actors.
#[allow(type_alias_bounds)]
pub type BoxedOwner<W: WebRequest> = Box<(Fn(&PreGrant) -> OwnerConsent<W::Response>) + Send + Sync>;

/// A request for an authorization code.
///
/// Originates from code similar to this:
///
/// ```no_run
/// # extern crate actix_web;
/// # extern crate futures;
/// # extern crate oxide_auth;
/// use oxide_auth::frontends::actix::OAuth;
/// # use oxide_auth::frontends::actix::message::AuthorizationCode;
/// # use oxide_auth::code_grant::frontend::{OwnerAuthorization, OAuthError};
/// # use oxide_auth::frontends::actix::ResolvedResponse;
/// # use actix_web::HttpRequest;
/// # use futures::Future;
/// # fn main() {
/// let handler = |request: HttpRequest| {
///     request.oauth2()
///         .authorization_code(|pre_grant|
///             OwnerAuthorization::Denied
///         ) // a future
///         .and_then(|message: AuthorizationCode|
/// # -> Result<(), OAuthError> { // some future
///             unimplemented!()
/// # }
///         );
/// };
/// # }
/// ```
pub struct AuthorizationCode<W: WebRequest=ResolvedRequest>(pub W);

/// A request for a bearer token.
///
/// Originates from code similar to this:
///
/// ```no_run
/// # extern crate actix_web;
/// # extern crate futures;
/// # extern crate oxide_auth;
/// use oxide_auth::frontends::actix::OAuth;
/// # use oxide_auth::frontends::actix::message::AccessToken;
/// # use oxide_auth::code_grant::frontend::{OwnerAuthorization, OAuthError};
/// # use oxide_auth::frontends::actix::ResolvedResponse;
/// # use actix_web::HttpRequest;
/// # use futures::Future;
/// # fn main() {
/// let handler = |request: HttpRequest| {
///     request.oauth2()
///         .access_token() // a future
///         .and_then(|message: AccessToken|
/// # -> Result<(), OAuthError> { // some future
///             unimplemented!()
/// # }
///         );
/// };
/// # }
/// ```
pub struct AccessToken<W: WebRequest=ResolvedRequest>(pub W);


/// A request for a resource, utilizing a bearer token.
///
/// Originates from code similar to this:
///
/// ```no_run
/// # extern crate actix_web;
/// # extern crate futures;
/// # extern crate oxide_auth;
/// use oxide_auth::frontends::actix::OAuth;
/// # use oxide_auth::frontends::actix::message::Guard;
/// # use oxide_auth::code_grant::frontend::{OwnerAuthorization, OAuthError};
/// # use oxide_auth::frontends::actix::ResolvedResponse;
/// # use actix_web::HttpRequest;
/// # use futures::Future;
/// # fn main() {
/// let handler = |request: HttpRequest| {
///     request.oauth2()
///         .guard() // a future
///         .and_then(|message: Guard|
/// # -> Result<(), OAuthError> { // some future
///             unimplemented!()
/// # }
///         );
/// };
/// # }
/// ```
pub struct Resource<W: WebRequest=ResolvedRequest>(pub W);

impl<W: WebRequest> Message for AuthorizationCode<W> 
where
    W: Send + Sync + 'static,
    W::Response: Send + Sync + 'static
{
    type Result = Result<W::Response, W::Error>;
}

impl<W: WebRequest> Message for AccessToken<W> 
where
    W: Send + Sync + 'static,
    W::Response: Send + Sync + 'static
{
    type Result = Result<W::Response, W::Error>;
}

impl<W: WebRequest> Message for Resource<W> 
where
    W: Send + Sync + 'static
{
    type Result = Result<(), Result<W::Response, W::Error>>;
}
