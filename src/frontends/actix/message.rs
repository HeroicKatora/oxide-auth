//! Provides actix message encapsulations.
//!
//! The http types, especially `HttpRequest` can not be shared across threads.  Therefore,
//! the relevant information is extracted into special message types first.
use super::actix::prelude::Message;

use super::resolve::{ResolvedRequest, ResolvedResponse};
use code_grant::frontend::{OAuthError, OwnerAuthorization, PreGrant};

/// Approves or denies are grant request based on owner information.
///
/// This is basically and sendable version of the much more generic `OwnerAuthorizer` concept
/// found in the basic code grant frontend.  All necessary data for validation needs to be
/// owned (and `Sync`) because the request struct of `actix_web` can not be sent between all
/// actors.
pub type BoxedOwner = Box<(Fn(&PreGrant) -> OwnerAuthorization<ResolvedResponse>) + Send + Sync>;

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
pub struct AuthorizationCode {
    pub(super) request: ResolvedRequest,
    pub(super) owner: BoxedOwner,
}

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
pub struct AccessToken(pub(super) ResolvedRequest);


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
pub struct Guard(pub(super) ResolvedRequest);

impl Message for AuthorizationCode {
    type Result = Result<ResolvedResponse, OAuthError>;
}

impl Message for AccessToken {
    type Result = Result<ResolvedResponse, OAuthError>;
}

impl Message for Guard {
    type Result = Result<(), OAuthError>;
}
