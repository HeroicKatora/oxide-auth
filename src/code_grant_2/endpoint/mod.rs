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

use std::borrow::{Borrow, Cow};
use std::cell::Cell;
use std::collections::HashMap;
use std::error;
use std::marker::PhantomData;
use std::fmt;
use std::str::from_utf8;

use primitives::authorizer::Authorizer;
use primitives::issuer::{Issuer, IssuedToken};
use primitives::grant::Grant;
use primitives::registrar::{ClientUrl, BoundClient, Registrar, RegistrarError, RegisteredClient};
use primitives::scope::Scope;

use super::accesstoken::{
    Extension as AccessTokenExtension,
    Endpoint as AccessTokenEndpoint,
    PrimitiveError as AccessTokenPrimitiveError};
use super::authorization::ErrorUrl;
use super::guard::{
    Error as ResourceError,
    /*Extension as GuardExtension,*/
    Endpoint as GuardEndpoint};

use url::Url;
use base64;

pub use primitives::registrar::PreGrant;
pub use self::authorization::*;

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

/// Allows access to the query parameters in an url or a body.
///
/// Use one of the listed implementations below.
///
/// You should generally not have to implement this trait yourself, and if you do there are
/// additional requirements on your implementation to guarantee standard conformance. Therefore the
/// trait is marked as `unsafe`.
pub unsafe trait QueryParameter {
    /// Get the **unique** value associated with a key.
    ///
    /// If there are multiple values, return `None`. This is very important to guarantee
    /// conformance to the RFC. Afaik it prevents potentially subverting validation middleware,
    /// order dependent processing, or simple confusion between different components who parse the
    /// query string from different ends.
    fn unique_value(&self, key: &str) -> Option<Cow<str>>;

    /// Guarantees that one can grab an owned copy.
    fn normalize(&self) -> NormalizedParameter;
}

/// The query parameter normal form.
///
/// When a request wants to give access to its query or body parameters by reference, it can do so
/// by a reference of the particular trait. But when the representation of the query is not stored
/// in the memory associated with the request, it needs to be allocated to outlive the borrow on
/// the request.  This allocation may as well perform the minimization/normalization into a
/// representation actually consumed by the backend. This normal form thus encapsulates the
/// associated `clone-into-normal form` by various possible constructors from references [WIP].
///
/// This gives rise to a custom `Cow<QueryParameter>` instance by requiring that normalization into
/// memory with unrelated lifetime is always possible.
///
/// Internally a hashmap but this may change due to optimizations.
#[derive(Clone, Debug, Default)]
pub struct NormalizedParameter {
    inner: HashMap<Cow<'static, str>, Cow<'static, str>>,
}

unsafe impl QueryParameter for NormalizedParameter {
    fn unique_value(&self, key: &str) -> Option<Cow<str>> {
        self.inner.get(key).cloned()
    }

    fn normalize(&self) -> NormalizedParameter {
        self.clone()
    }
}

impl Borrow<QueryParameter> for NormalizedParameter {
    fn borrow(&self) -> &(QueryParameter + 'static) {
        self
    }
}

impl ToOwned for QueryParameter {
    type Owned = NormalizedParameter;

    fn to_owned(&self) -> Self::Owned {
        self.normalize()
    }
}

unsafe impl QueryParameter for HashMap<String, String> {
    fn unique_value(&self, key: &str) -> Option<Cow<str>> {
        self.get(key).cloned().map(Cow::Owned)
    }

    fn normalize(&self) -> NormalizedParameter {
        let inner = self.iter()
            .map(|(key, val)| (Cow::Owned(key.to_string()), Cow::Owned(val.to_string())))
            .collect();

        NormalizedParameter {
            inner,
        }
    }
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
/// Needs `Sized` because it is constructed within the flow, not externally injected and only
/// modified. Note that this may change in a future version of the api. But currently all popular
/// web server implementations I know of construct responses within the handler.
pub trait WebResponse: Sized {
    /// The error generated when trying to construct an unhandled or invalid response.
    type Error;

    /// A response which will redirect the user-agent to which the response is issued.
    fn redirect(url: Url) -> Result<Self, Self::Error>;

    /// A pure text response with no special media type set.
    fn text(text: &str) -> Result<Self, Self::Error>;

    /// Json repsonse data, with media type `aplication/json.
    fn json(data: &str) -> Result<Self, Self::Error>;

    /// Set the response status to 400
    fn as_client_error(self) -> Result<Self, Self::Error>;

    /// Set the response status to 401
    fn as_unauthorized(self) -> Result<Self, Self::Error>;

    /// Add an `WWW-Authenticate` header
    fn with_authorization(self, kind: &str) -> Result<Self, Self::Error>;
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

    /// Try to recover from a primitive error during access token flow.
    ///
    /// Depending on an endpoints additional information about its primitives or extensions, it may
    /// try to recover from this error by resetting states and returning a `TryAgain` overall. The
    /// default implementation returns with an opaque, converted `OAuthError::PrimitiveError`.
    fn access_token_error(&mut self, _error: AccessTokenPrimitiveError) -> Self::Error {
        OAuthError::PrimitiveError.into()
    }

    /// Construct a redirect for the error. Here the response may choose to augment the error with
    /// additional information (such as help websites, description strings), hence the default
    /// implementation which does not do any of that.
    fn redirect_error(&mut self, target: ErrorRedirect) -> Result<Request::Response, Self::Error> {
        Request::Response::redirect(target.into()).map_err(Into::into)
    }
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
}

/// Checks consent with the owner of a resource, identified in a request.
pub trait OwnerSolicitor<Request: WebRequest> {
    /// Ensure that a user (resource owner) is currently authenticated (for example via a session
    /// cookie) and determine if he has agreed to the presented grants.
    fn check_consent(&mut self, &mut Request, pre_grant: &PreGrant) -> OwnerConsent<Request::Response>;
}

/// All relevant methods for granting access token from authorization codes.
pub struct GrantFlow<'a> {
    registrar: Cell<&'a Registrar>,
    authorizer: Cell<Option<&'a mut Authorizer>>,
    issuer: Cell<Option<&'a mut Issuer>>,
    extensions: Vec<&'a AccessTokenExtension>,
}

/// All relevant methods for checking authorization for access to a resource.
pub struct AccessFlow<'a> {
    issuer: Cell<Option<&'a mut Issuer>>,
    scopes: &'a [Scope],
}

/// Errors which should not or need not be communicated to the requesting party but which are of
/// interest to the server. See the documentation for each enum variant for more documentation on
/// each as some may have an expected response. These include badly formatted headers or url encoded
/// body, unexpected parameters, or security relevant required parameters.
#[derive(Debug)]
pub enum OAuthError {
    /// Deny authorization to the client by essentially dropping the request.
    ///
    /// For example, this response is given when an incorrect client has been provided in the
    /// authorization request in order to avoid potential indirect denial of service vulnerabilities.
    DenySilently,

    /// Authorization to access the resource has not been granted.
    AccessDenied {
        /// The underlying cause for denying access.
        ///
        /// The http authorization header is set according to this field.
        error: ResourceError,
    },

    /// One of the primitives used to complete the operation failed.
    PrimitiveError,

    /// The incoming request was malformed.
    ///
    /// This implies that it did not change any internal state.
    InvalidRequest,
}

impl OAuthError {
    /// Create a response for the request that produced this error.
    ///
    /// After inspecting the error returned from the library API and doing any necessary logging,
    /// this methods allows easily turning the error into a template (or complete) response to the
    /// client.  It takes care of setting the necessary headers.
    pub fn response_or<W: WebResponse>(self, internal_error: W) -> W {
        match self {
            OAuthError::DenySilently | OAuthError::InvalidRequest => W::text("")
                .and_then(|response| response.as_client_error()),
            OAuthError::AccessDenied { error } => W::text("")
                .and_then(|response| response.with_authorization(&error.www_authenticate())),
            OAuthError::PrimitiveError => return internal_error,
        }.unwrap_or(internal_error)
    }

    /// Create a response for the request that produced this error.
    ///
    /// After inspecting the error returned from the library API and doing any necessary logging,
    /// this methods allows easily turning the error into a template (or complete) response to the
    /// client.  It takes care of setting the necessary headers.
    pub fn response_or_else<W, F>(self, internal_error: F) -> W
        where F: FnOnce() -> W, W: WebResponse
    {
        match self {
            OAuthError::DenySilently | OAuthError::InvalidRequest => W::text("")
                .and_then(|response| response.as_client_error()),
            OAuthError::AccessDenied { error } => W::text("")
                .and_then(|response| response.with_authorization(&error.www_authenticate())),
            OAuthError::PrimitiveError => return internal_error(),
        }.unwrap_or_else(|_| internal_error())
    }
}

impl fmt::Display for OAuthError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        fmt.write_str("OAuthError")
    }
}

impl error::Error for OAuthError {
    fn description(&self) -> &str {
        "OAuthError"
    }
}
