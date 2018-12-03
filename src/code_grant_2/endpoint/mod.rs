//! General algorithms for endpoints.
//!
//! An endpoint is concerned with executing the abstract behaviours given by the backend in terms
//! of the actions of the endpoint types. This means translating Redirect errors to the correct
//! Redirect http response for example or optionally sending internal errors to loggers. The
//! frontends, which are the bindings to particular server libraries, can instantiate the endpoint
//! api or simple reuse existing types.
//!
//! To ensure the adherence to the oauth2 rfc and the improve general implementations, some control
//! flow of incoming packets is specified here instead of the frontend implementations.  Instead,
//! traits are offered to make this compatible with other endpoints. In theory, this makes
//! endpoints pluggable which could improve testing.
//!
//! Custom endpoint
//! ---------------
//! In order to not place restrictions on the web server library in use, it is possible to
//! implement an endpoint completely with user defined types.
//!
//! This requires custom, related implementations of [`WebRequest`] and [`WebResponse`].
//! _WARNING_: Custom endpoints MUST ensure a secure communication layer with confidential clients.
//! This means using TLS for communication over http (although there are currently discussions to
//! consider communication to `localhost` as always occuring in a secure context).
//!
//! After receiving an authorization grant, access token or access request, initiate the respective
//! flow by collecting the [`Authorizer`], [`Issuer`], and [`Registrar`] instances. For example:
//!
//! ```no_run
//! extern crate oxide_auth;
//! # extern crate url;
//! # use std::borrow::Cow;
//! # use std::collections::HashMap;
//! # use std::vec::Vec;
//! use oxide_auth::code_grant::frontend::{OAuthError, QueryParameter, WebRequest, WebResponse};
//! use oxide_auth::code_grant::frontend::{GrantFlow};
//! use oxide_auth::primitives::prelude::*;
//! use url::Url;
//! struct MyRequest { /* user defined */ }
//! struct MyResponse { /* user defined */ }
//!
//! impl WebRequest for MyRequest {
//!     type Error = OAuthError; /* Custom type permitted but this is easier */
//!     type Response = MyResponse;
//!     /* Implementation of the traits' methods */
//! # fn query(&mut self) -> Result<QueryParameter, ()> { Err(()) }
//! # fn urlbody(&mut self) -> Result<QueryParameter, ()> { Err(()) }
//! # fn authheader(&mut self) -> Result<Option<Cow<str>>, ()> { Err(()) }
//! }
//!
//! impl WebResponse for MyResponse {
//!     type Error = OAuthError;
//!     /* Implementation of the traits' methods */
//! # fn redirect(url: Url) -> Result<Self, Self::Error> { Ok(MyResponse {}) }
//! # fn text(text: &str) -> Result<Self, Self::Error> { Ok(MyResponse {}) }
//! # fn json(data: &str) -> Result<Self, Self::Error> { Ok(MyResponse {}) }
//! # fn as_client_error(self) -> Result<Self, Self::Error> { Ok(MyResponse {}) }
//! # fn as_unauthorized(self) -> Result<Self, Self::Error> { Ok(MyResponse {}) }
//! # fn with_authorization(self, kind: &str) -> Result<Self, Self::Error> { Ok(MyResponse {}) }
//! }
//!
//! struct State<'a> {
//!     registrar: &'a mut Registrar,
//!     authorizer: &'a mut Authorizer,
//!     issuer: &'a mut Issuer,
//! }
//!
//! fn handle(state: State, request: MyRequest) -> Result<MyResponse, OAuthError> {
//!     GrantFlow::new(state.registrar, state.authorizer, state.issuer)
//!         .handle(request)
//! }
//! # pub fn main() { }
//! ```
//!
//! [`WebRequest`]: trait.WebRequest.html
//! [`WebResponse`]: trait.WebResponse.html
//! [`Authorizer`]: ../../primitives/authorizer/trait.Authorizer.html
//! [`Issuer`]: ../../primitives/issuer/trait.Issuer.html
//! [`Registrar`]: ../../primitives/registrar/trait.Registrar.html
mod authorization;
mod accesstoken;
mod error;
mod resource;
mod query;

use std::borrow::Cow;
use std::cell::Cell;
use std::marker::PhantomData;

use primitives::authorizer::Authorizer;
use primitives::issuer::Issuer;
use primitives::registrar::Registrar;
use primitives::scope::Scope;

use super::accesstoken::{
    Extension as AccessTokenExtension,
    PrimitiveError as AccessTokenPrimitiveError};
use super::authorization::ErrorUrl;
use super::guard::{
    /*Extension as GuardExtension,*/
    Error as ResourceError};

use url::Url;

pub use primitives::registrar::PreGrant;
pub use self::authorization::*;
pub use self::accesstoken::*;
pub use self::error::OAuthError;
pub use self::resource::*;
pub use self::query::*;

/// Answer from OwnerAuthorizer to indicate the owners choice.
pub enum OwnerConsent<Response: WebResponse> {
    /// The owner did not authorize the client.
    Denied,

    /// The owner has not yet decided, i.e. the returned page is a form for the user.
    InProgress(Response),

    /// Authorization was granted by the specified user.
    Authorized(String),

    /// An error occurred while checking authorization.
    Error(Response::Error),
}

/// An error occuring during authorization, convertible to the redirect url with which to respond.
pub struct ErrorRedirect(ErrorUrl);

impl Into<Url> for ErrorRedirect {
    fn into(self) -> Url {
        self.0.into()
    }
}

/// Abstraction of web requests with several different abstractions and constructors needed by an
/// endpoint. It is assumed to originate from an HTTP request, as defined in the scope of the rfc,
/// but theoretically other requests are possible.
pub trait WebRequest {
    /// The error generated from access of malformed or invalid requests.
    type Error;

    /// The corresponding type of Responses returned from this module.
    type Response: WebResponse<Error=Self::Error>;

    /// Retrieve a parsed version of the url query.
    ///
    /// An Err return value indicates a malformed query or an otherwise malformed WebRequest. Note
    /// that an empty query should result in `Ok(HashMap::new())` instead of an Err.
    fn query(&mut self) -> Result<Cow<QueryParameter + 'static>, Self::Error>;

    /// Retrieve the parsed `application/x-form-urlencoded` body of the request.
    ///
    /// An Err value / indicates a malformed body or a different Content-Type.
    fn urlbody(&mut self) -> Result<Cow<QueryParameter + 'static>, Self::Error>;

    /// Contents of the authorization header or none if none exists. An Err value indicates a
    /// malformed header or request.
    fn authheader(&mut self) -> Result<Option<Cow<str>>, Self::Error>;
}

/// Response representation into which the Request is transformed by the code_grant types.
///
/// At most one of the methods `body_text`, `body_json` will be called. Some flows will
/// however not call any of those methods.
pub trait WebResponse {
    /// The error generated when trying to construct an unhandled or invalid response.
    type Error;

    /// Set the response status to 200.
    fn ok(&mut self) -> Result<(), Self::Error>;

    /// A response which will redirect the user-agent to which the response is issued.
    fn redirect(&mut self, url: Url) -> Result<(), Self::Error>;

    /// Set the response status to 400.
    fn client_error(&mut self) -> Result<(), Self::Error>;

    /// Set the response status to 401 and add a `WWW-Authenticate` header.
    fn unauthorized(&mut self, header_value: &str) -> Result<(), Self::Error>;

    /// A pure text response with no special media type set.
    fn body_text(&mut self, text: &str) -> Result<(), Self::Error>;

    /// Json repsonse data, with media type `aplication/json.
    fn body_json(&mut self, data: &str) -> Result<(), Self::Error>;
}

/// Fuses requests and primitives into a coherent system to give a response.
///
/// There are multiple different valid ways to produce responses and react to internal errors for a
/// single request type. This trait should provide those mechanisms, including trying to recover
/// from primitive errors where appropriate.
///
/// To reduce the number of necessary impls and provide a single interface to a single trait, this
/// trait defines accessor methods for all possibly needed primitives. Note that not all flows
/// actually access all primitives. Thus, an implementation does not necessarily have to return
/// something in `registrar`, `authorizer`, `issuer_mut` but failing to do so will also fail flows
/// that try to use them.
pub trait Endpoint<Request: WebRequest> {
    /// The error typed used as the error representation of each flow.
    type Error: From<OAuthError> + From<Request::Error>;

    /// A registrar if this endpoint can access one.
    ///
    /// Returning `None` will implicate failing any flow that requires a registrar but does not
    /// have any effect on flows that do not require one.
    fn registrar(&self) -> Option<&Registrar>;
    
    /// An authorizer if this endpoint can access one.
    ///
    /// Returning `None` will implicate failing any flow that requires an authorizer but does not
    /// have any effect on flows that do not require one.
    fn authorizer_mut(&mut self) -> Option<&mut Authorizer>;

    /// An issuer if this endpoint can access one.
    ///
    /// Returning `None` will implicate failing any flow that requires an issuer but does not have
    /// any effect on flows that do not require one.
    fn issuer_mut(&mut self) -> Option<&mut Issuer>;

    /// Return the system that checks owner consent.
    ///
    /// Returning `None` will implicated failing the authorization code flow but does have any
    /// effect on other flows.
    fn owner_solicitor(&mut self) -> Option<&mut OwnerSolicitor<Request>>;

    /// Determine the required scopes for a request.
    ///
    /// The client must fulfill any one scope, so returning an empty slice will always deny the
    /// request.
    fn scopes(&mut self, request: &mut Request) -> &[Scope];

    /// Try to recover from a primitive error during access token flow.
    ///
    /// Depending on an endpoints additional information about its primitives or extensions, it may
    /// try to recover from this error by resetting states and returning a `TryAgain` overall. The
    /// default implementation returns with an opaque, converted `OAuthError::PrimitiveError`.
    fn access_token_error(&mut self, _error: AccessTokenPrimitiveError) -> Self::Error {
        OAuthError::PrimitiveError.into()
    }

    /// Generate a prototype response.
    ///
    /// The endpoint can rely on this being called at most once for each flow, if it wants
    /// to preallocate the response or return a handle on an existing prototype.
    fn response(&mut self, kind: ResponseKind) -> Result<Request::Response, Self::Error>;
}

impl<'a, R: WebRequest, E: Endpoint<R>> Endpoint<R> for &'a mut E {
    type Error = E::Error;

    fn registrar(&self) -> Option<&Registrar> {
        (**self).registrar()
    }
    
    fn authorizer_mut(&mut self) -> Option<&mut Authorizer> {
        (**self).authorizer_mut()
    }

    fn issuer_mut(&mut self) -> Option<&mut Issuer> {
        (**self).issuer_mut()
    }

    fn access_token_error(&mut self, error: AccessTokenPrimitiveError) -> Self::Error {
        (**self).access_token_error(error)
    }

    fn owner_solicitor(&mut self) -> Option<&mut OwnerSolicitor<R>> {
        (**self).owner_solicitor()
    }

    fn scopes(&mut self, request: &mut R) -> &[Scope] {
        (**self).scopes(request)
    }

    fn response(&mut self, kind: ResponseKind) -> Result<R::Response, Self::Error> {
        (**self).response(kind)
    }
}

/// Checks consent with the owner of a resource, identified in a request.
pub trait OwnerSolicitor<Request: WebRequest> {
    /// Ensure that a user (resource owner) is currently authenticated (for example via a session
    /// cookie) and determine if he has agreed to the presented grants.
    fn check_consent(&mut self, &mut Request, pre_grant: &PreGrant) -> OwnerConsent<Request::Response>;
}

/// Lists the differnet reasons for creating a response to the client.
///
/// Not all responses indicate failure. A redirect will also occur in the a regular of providing an
/// access token to the third party client.
pub enum ResponseKind {
    /// Authorization to access the resource has not been granted.
    Unauthorized {
        /// The underlying cause for denying access.
        ///
        /// The http authorization header is to be set according to this field.
        error: Option<ResourceError>,
    },

    /// Redirect the user-agent to another url.
    ///
    /// The endpoint has the opportunity to inspect and modify error information to some extent.
    /// For example to log an error rate or to provide a pointer to a custom human readable
    /// explanation page. The response will generally not contain a body.
    Redirect,

    /// The request did not conform to specification or was otheriwse invalid.
    ///
    /// As such, it was not handled further. Some processes still warrant a response body to be
    /// set in the case of an invalid request, containing additional information for the client.
    /// For example, an authorized client sending a malformed but authenticated request for an
    /// access token will receive additional hints on the cause of his mistake.
    Invalid,

    /// An expected, normal response whose content requires precise semantics.
    Ok,
}
