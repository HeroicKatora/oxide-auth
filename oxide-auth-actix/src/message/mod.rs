//! Provides actix message encapsulations.
//!
//! The http types, especially `HttpRequest` can not be shared across threads.  Therefore,
//! the relevant information is extracted into special message types first using the `OAuth` trait
//! found in the module above.
mod authorizer;
mod issuer;
mod registrar;

use actix::prelude::Message;

use super::ResourceProtection;
use super::request::{OAuthRequest as ResolvedRequest};
use oxide_auth::primitives::grant::Grant;
use oxide_auth::endpoint::WebRequest;

pub use self::authorizer::{Authorize, Extract};
pub use self::issuer::{Issue, RecoverToken, RecoverRefresh, Refresh};
pub use self::registrar::{BoundRedirect, Check, Negotiate};


/// A request for an authorization code from an endpoint actor.
///
/// ## Example
///
/// Here is a way to request an authorization code response from some actix recipient.
///
/// ```no_run
/// # extern crate actix;
/// # extern crate actix_web;
/// # extern crate futures;
/// # extern crate oxide_auth_actix;
/// use oxide_auth_actix::{OAuth, OAuthError, OAuthResponse};
/// use oxide_auth_actix::message::AuthorizationCode;
/// # use oxide_auth_actix::request::OAuthRequest;
/// # use actix::Recipient;
/// # use actix_web::HttpRequest;
/// # use futures::Future;
/// # fn main() {
///
/// fn handle(request: HttpRequest, recipient: Recipient<AuthorizationCode>)
///     -> impl Future<Item=OAuthResponse, Error=OAuthError>
/// {
///     request.oauth2()
///         .and_then(move |request| recipient
///             .send(request.authorization_code())
///             // Merge `MailboxError` and response ´OAuthError`
///             .map_err(|_| OAuthError::DenySilently)
///             .and_then(|x| x))
/// }
/// # }
/// ```
pub struct AuthorizationCode<W: WebRequest=ResolvedRequest>(pub W);

/// A request for a bearer token.
///
/// ## Example
///
/// Here is a way to request an access token response from some actix recipient.
///
/// ```no_run
/// # extern crate actix;
/// # extern crate actix_web;
/// # extern crate futures;
/// # extern crate oxide_auth_actix;
/// use oxide_auth_actix::{OAuth, OAuthError, OAuthResponse};
/// use oxide_auth_actix::message::AccessToken;
/// # use oxide_auth_actix::request::OAuthRequest;
/// # use actix::Recipient;
/// # use actix_web::HttpRequest;
/// # use futures::Future;
/// # fn main() {
///
/// fn handle(request: HttpRequest, recipient: Recipient<AccessToken>)
///     -> impl Future<Item=OAuthResponse, Error=OAuthError>
/// {
///     request.oauth2()
///         .and_then(move |request| recipient
///             .send(request.access_token())
///             // Merge `MailboxError` and response ´OAuthError`
///             .map_err(|_| OAuthError::DenySilently)
///             .and_then(|x| x))
/// }
/// # }
/// ```
pub struct AccessToken<W: WebRequest=ResolvedRequest>(pub W);

/// A request for a resource, utilizing a bearer token.
///
/// ## Example
///
/// Here is a way to test an authorizing request against an actix recipient.
///
/// ```no_run
/// # extern crate actix;
/// # extern crate actix_web;
/// # extern crate futures;
/// # extern crate oxide_auth_actix;
/// use oxide_auth_actix::{Grant, OAuth, OAuthError, OAuthResponse, ResourceProtection};
/// use oxide_auth_actix::message::Resource;
/// # use oxide_auth_actix::request::OAuthRequest;
/// # use actix::Recipient;
/// # use actix_web::HttpRequest;
/// # use futures::Future;
/// # fn main() {
///
/// fn handle(request: HttpRequest, recipient: Recipient<Resource>)
///     -> impl Future<Item=Grant, Error=ResourceProtection<OAuthResponse>>
/// {
///     request.oauth2()
///         .map_err(ResourceProtection::Error)
///         .and_then(move |request| recipient
///             .send(request.resource())
///             // Merge `MailboxError` and response ´OAuthError`
///             .map_err(|_| ResourceProtection::Error(OAuthError::DenySilently))
///             .and_then(|x| x))
/// }
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
    type Result = Result<Grant, ResourceProtection<W::Response>>;
}
