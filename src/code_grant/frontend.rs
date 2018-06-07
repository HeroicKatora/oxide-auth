//! General algorithms for frontends.
//!
//! The frontend is concerned with executing the abstract behaviours given by the backend in terms
//! of the actions of the frontend types. This means translating Redirect errors to the correct
//! Redirect http response for example or optionally sending internal errors to loggers.
//!
//! To ensure the adherence to the oauth2 rfc and the improve general implementations, some control
//! flow of incoming packets is specified here instead of the frontend implementations.
//! Instead, traits are offered to make this compatible with other frontends. In theory, this makes
//! the frontend pluggable which could improve testing.
//!
//! Custom frontend
//! ---------------
//! In order to not place restrictions on the web server library in use, it is possible to
//! implement a frontend completely with user defined types.
//!
//! This requires custom, related implementations of [`WebRequest`] and [`WebResponse`].
//! _WARNING_: Custom frontends MUST ensure a secure communication layer with confidential clients.
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

use std::borrow::Cow;
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

use super::backend::*;
use super::extensions::{AccessTokenExtension, CodeExtension};

use url::Url;
use base64;

pub use primitives::registrar::PreGrant;

/// Holds the decode query fragments from the url. This does not hold the excess parameters with a
/// Cow, as we need to have a mutable reference to it for the authorization handler.
struct AuthorizationParameter<'a> {
    valid: bool,
    method: Option<Cow<'a, str>>,
    client_id: Option<Cow<'a, str>>,
    scope: Option<Cow<'a, str>>,
    redirect_uri: Option<Cow<'a, str>>,
    state: Option<Cow<'a, str>>,
    extensions: QueryParameter<'a>,
}

/// Answer from OwnerAuthorizer to indicate the owners choice.
pub enum OwnerAuthorization<Response: WebResponse> {
    /// The owner did not authorize the client.
    Denied,

    /// The owner has not yet decided, i.e. the returned page is a form for the user.
    InProgress(Response),

    /// Authorization was granted by the specified user.
    Authorized(String),

    /// An error occurred while checking authorization.
    Error(Response::Error),
}

struct AccessTokenParameter<'a> {
    valid: bool,
    client_id: Option<Cow<'a, str>>,
    redirect_uri: Option<Cow<'a, str>>,
    grant_type: Option<Cow<'a, str>>,
    code: Option<Cow<'a, str>>,
    authorization: Option<(String, Vec<u8>)>,
    extensions: QueryParameter<'a>,
}

struct GuardParameter<'a> {
    valid: bool,
    token: Option<Cow<'a, str>>,
}

/// Representation of query parameters with a single value for each key.
///
/// All enums support Copy-on-Write values, useful when the extracted representation is stored
/// within the request but also when the representation is returned as a value.
pub enum SingleValueQuery<'a> {
    /// Choose this if the query parameters are recovered as references to the underlying data.
    StrValue(Cow<'a, HashMap<&'a str, &'a str>>),

    /// Choose this if the query parameters are copied from the underlying data.
    StringValue(Cow<'a, HashMap<String, String>>),

    /// Some query parameters are copied from the underlying data and some are references.
    CowValue(Cow<'a, HashMap<Cow<'a, str>, Cow<'a, str>>>),
}

/// Representation of query parameters allowing multiple values per key.
///
/// All enums support Copy-on-Write values, useful when the extracted representation is stored
/// within the request but also when the representation is returned as a value.
pub enum MultiValueQuery<'a> {
    /// Choose this if the query parameters are recovered as references to the underlying data.
    StrValues(Cow<'a, HashMap<&'a str, Vec<&'a str>>>),

    /// Choose this if the query parameters are copied from the underlying data.
    StringValues(Cow<'a, HashMap<String, Vec<String>>>),

    /// Some query parameters are copied from the underlying data and some are references.
    CowValues(Cow<'a, HashMap<Cow<'a, str>, Vec<Cow<'a, str>>>>)
}

/// A versatile representation of url encoded query parameters.
///
/// The return value of both urlencoded entities in the `WebRequest`.  This enum encompasses
/// several different styles and ownerships for decoding url query parameters.  It tries to make
/// as few assumptions about internal representations of the concrete type while keeping in mind
/// that conversions are not zero-copy.  For example, neither of `HashMap<String, String>` and
/// `HashMap<Cow<str>, Cow<str>>` could be easily converted into the other and there does not
/// exist a common type.
///
/// Several implementations also support multiple values for a single key which is not useful in
/// any of the supported OAuth 2.0 parameters.
pub enum QueryParameter<'a> {
    /// For web frameworks which only support single value query parameters.
    SingleValue(SingleValueQuery<'a>),

    /// For web frameworks with multi map queries.
    MultiValue(MultiValueQuery<'a>),
}

/// An error occuring during authorization, convertible to the redirect url with which to respond.
pub struct ErrorRedirect(ErrorUrl);

impl Into<Url> for ErrorRedirect {
    fn into(self) -> Url {
        self.0.into()
    }
}

/// Abstraction of web requests with several different abstractions and constructors needed by this
/// frontend. It is assumed to originate from an HTTP request, as defined in the scope of the rfc,
/// but theoretically other requests are possible.
pub trait WebRequest {
    /// The error generated from access of malformed or invalid requests.
    type Error: From<OAuthError>;

    /// The corresponding type of Responses returned from this module.
    type Response: WebResponse<Error=Self::Error>;

    /// Retrieve a parsed version of the url query. An Err return value indicates a malformed query
    /// or an otherwise malformed WebRequest. Note that an empty query should result in
    /// `Ok(HashMap::new())` instead of an Err.
    fn query(&mut self) -> Result<QueryParameter, ()>;

    /// Retriev the parsed `application/x-form-urlencoded` body of the request. An Err value
    /// indicates a malformed body or a different Content-Type.
    fn urlbody(&mut self) -> Result<QueryParameter, ()>;

    /// Contents of the authorization header or none if none exists. An Err value indicates a
    /// malformed header or request.
    fn authheader(&mut self) -> Result<Option<Cow<str>>, ()>;
}

/// Response representation into which the Request is transformed by the code_grant types.
pub trait WebResponse where Self: Sized {
    /// The error generated when trying to construct an unhandled or invalid response.
    type Error: From<OAuthError>;

    /// A response which will redirect the user-agent to which the response is issued.
    fn redirect(url: Url) -> Result<Self, Self::Error>;

    /// A pure text response with no special media type set.
    fn text(text: &str) -> Result<Self, Self::Error>;

    /// Json repsonse data, with media type `aplication/json.
    fn json(data: &str) -> Result<Self, Self::Error>;

    /// Construct a redirect for the error. Here the response may choose to augment the error with
    /// additional information (such as help websites, description strings), hence the default
    /// implementation which does not do any of that.
    fn redirect_error(target: ErrorRedirect) -> Result<Self, Self::Error> {
        Self::redirect(target.into())
    }

    /// Set the response status to 400
    fn as_client_error(self) -> Result<Self, Self::Error>;
    /// Set the response status to 401
    fn as_unauthorized(self) -> Result<Self, Self::Error>;
    /// Add an `WWW-Authenticate` header
    fn with_authorization(self, kind: &str) -> Result<Self, Self::Error>;
}

/// Conveniently checks the authorization from a request.
pub trait OwnerAuthorizer<Request: WebRequest> {
    /// Ensure that a user (resource owner) is currently authenticated (for example via a session
    /// cookie) and determine if he has agreed to the presented grants.
    fn check_authorization(self, Request, pre_grant: &PreGrant) -> OwnerAuthorization<Request::Response>;
}

impl<'a> QueryParameter<'a> {
    /// Choose the most efficient (least copies) option. Either get a copy of the stored value
    /// if it is the only value or a copy of referenced value or return None if it does exist or
    /// if the value is not the only stored value.
    fn get(&self, key: &str) -> Option<Cow<'a, str>> {
        match self {
            &QueryParameter::SingleValue(
                SingleValueQuery::StrValue(
                    Cow::Borrowed(ref map))) => map.get(key).map(|st| Cow::Borrowed(*st)),
            &QueryParameter::SingleValue(
                SingleValueQuery::StrValue(
                    Cow::Owned(ref map))) => map.get(key).map(|st| Cow::Borrowed(*st)),
            &QueryParameter::SingleValue(
                SingleValueQuery::StringValue(
                    Cow::Borrowed(ref map))) => map.get(key).map(|st| Cow::Borrowed(st.as_str())),
            &QueryParameter::SingleValue(
                SingleValueQuery::StringValue(
                    // Since the map is owned, the lifetime 'a might be longer
                    Cow::Owned(ref map))) => map.get(key).cloned().map(Cow::Owned),
            &QueryParameter::SingleValue(
                SingleValueQuery::CowValue(
                    Cow::Borrowed(ref map))) => map.get(key).map(|st| Cow::Borrowed(&**st)),
            &QueryParameter::SingleValue(
                SingleValueQuery::CowValue(
                    // Since the map is owned, the lifetime 'a might be longer
                    Cow::Owned(ref map))) => map.get(key).cloned(),

            &QueryParameter::MultiValue(
                MultiValueQuery::StrValues(
                    Cow::Borrowed(ref map))) => match map.get(key) {
                        Some(vec) if vec.len() == 1
                            => Some(Cow::Borrowed(vec[0])),
                        _ => None,
                    },
            &QueryParameter::MultiValue(
                MultiValueQuery::StrValues(
                    Cow::Owned(ref map))) => match map.get(key) {
                        Some(vec) if vec.len() == 1
                            => Some(Cow::Borrowed(vec[0])),
                        _ => None,
                    },
            &QueryParameter::MultiValue(
                MultiValueQuery::StringValues(
                    Cow::Borrowed(ref map))) => match map.get(key) {
                        Some(vec) if vec.len() == 1
                            => Some(Cow::Borrowed(vec[0].as_str())),
                        _ => None,
                    },
            &QueryParameter::MultiValue(
                MultiValueQuery::StringValues(
                    Cow::Owned(ref map))) => match map.get(key) {
                        Some(vec) if vec.len() == 1
                            // Since the map is owned, the lifetime 'a might be longer
                            => Some(Cow::Owned(vec[0].clone())),
                        _ => None,
                    },
            &QueryParameter::MultiValue(
                MultiValueQuery::CowValues(
                    Cow::Borrowed(ref map))) => match map.get(key) {
                        Some(vec) if vec.len() == 1
                            => Some(Cow::Borrowed(&*vec[0])),
                        _ => None,
                    },
            &QueryParameter::MultiValue(
                MultiValueQuery::CowValues(
                    Cow::Owned(ref map))) => match map.get(key) {
                        Some(vec) if vec.len() == 1
                            // Since the map is owned, the lifetime 'a might be longer
                            => Some(vec[0].clone()),
                        _ => None,
                    },
        }
    }
}

impl<'l, W: WebRequest> From<&'l mut W> for AuthorizationParameter<'l> {
    fn from(val: &'l mut W) -> Self {
        let params = match val.query() {
            Err(()) => return Self::invalid(),
            Ok(query) => query,
        };

        AuthorizationParameter {
            valid: true,
            client_id: params.get("client_id"),
            scope: params.get("scope"),
            redirect_uri: params.get("redirect_uri"),
            state: params.get("state"),
            method: params.get("response_type"),
            extensions: params,
        }
    }
}

impl<'l> authorization::CodeRequest for AuthorizationParameter<'l> {
    fn valid(&self) -> bool {
        self.valid
    }

    fn client_id(&self) -> Option<Cow<str>> {
        self.client_id.clone()
    }

    fn scope(&self) -> Option<Cow<str>> {
        self.scope.clone()
    }

    fn redirect_uri(&self) -> Option<Cow<str>> {
        self.redirect_uri.clone()
    }

    fn state(&self) -> Option<Cow<str>> {
        self.state.clone()
    }

    fn method(&self) -> Option<Cow<str>> {
        self.method.clone()
    }

    fn extension(&self, key: &str) -> Option<Cow<str>> {
        self.extensions.get(key)
    }
}

impl<'l> AuthorizationParameter<'l> {
    fn invalid() -> Self {
        AuthorizationParameter {
            valid: false,
            method: None,
            client_id: None,
            scope: None,
            redirect_uri: None,
            state: None,
            extensions: QueryParameter::SingleValue(
                SingleValueQuery::CowValue(
                    Cow::Owned(HashMap::new())
                )
            ),
        }
    }
}

struct AuthorizationPrimitives<'a> {
    registrar: Cell<&'a Registrar>,
    authorizer: Cell<Option<&'a mut Authorizer>>,
}

/// All relevant methods for handling authorization code requests.
pub struct AuthorizationFlow<'a> {
    primitives: AuthorizationPrimitives<'a>,
    extensions: Vec<&'a CodeExtension>,
}

/// A processed authentication request that is waiting for authorization by the resource owner.
pub struct PendingAuthorization<'a, Req: WebRequest> {
    primitives: AuthorizationPrimitives<'a>,
    request: AuthorizationRequest,
    phantom: PhantomData<Req>,
}

/// Result type from processing an authentication request.
pub enum AuthorizationResult<'a, Request: WebRequest> {
    /// No error happened during processing and the resource owner can decide over the grant.
    Pending {
        /// The request passed in.
        request: Request,

        /// A utility struct with which the request can be decided.
        pending: PendingAuthorization<'a, Request>
    },

    /// The request was faulty, e.g. wrong client data.
    Failed(Request::Response),

    /// An internal error happened during the request.
    Error(Request::Error),
}

impl<'a> AuthorizationFlow<'a> {
    /// Initiate an authorization code token flow.
    pub fn new(registrar: &'a Registrar, authorizer: &'a mut Authorizer) -> Self {
        AuthorizationFlow {
            primitives: AuthorizationPrimitives::new(registrar, authorizer),
            extensions: Vec::new(),
        }
    }

    /// Add an extension to access token handling.
    pub fn with_extension(mut self, extension: &'a CodeExtension) -> Self {
        self.extensions.push(extension);
        self
    }

    /// React to an authorization code request, handling owner approval with a specified handler.
    pub fn handle<Req>(self, mut request: Req)
    -> AuthorizationResult<'a, Req> where
        Req: WebRequest,
    {
        let negotiated = {
            let urldecoded = AuthorizationParameter::from(&mut request);
            match authorization_code(&self.primitives, &urldecoded, self.extensions.as_slice()) {
                Err(CodeError::Ignore)
                    => return AuthorizationResult::Error(OAuthError::DenySilently.into()),
                Err(CodeError::Redirect(url))
                    => return AuthorizationResult::from_fail(
                        Req::Response::redirect_error(ErrorRedirect(url))),
                Ok(negotiated) => negotiated,
            }
        };

        AuthorizationResult::Pending {
            request,
            pending: PendingAuthorization {
                primitives: self.primitives,
                request: negotiated,
                phantom: PhantomData,
            }
        }
    }
}

impl<'a, Request: WebRequest> AuthorizationResult<'a, Request> {
    /// Utility method which can be used instead of matching to decide the request.
    pub fn complete<F>(self, f: F) -> Result<Request::Response, Request::Error>
    where F: OwnerAuthorizer<Request> {
        match self {
            AuthorizationResult::Pending {
                request,
                pending,
            } => match f.check_authorization(request, pending.request.pre_grant()) {
                OwnerAuthorization::InProgress(response) => Ok(response),
                OwnerAuthorization::Authorized(owner) => pending.authenticated(owner),
                OwnerAuthorization::Denied => pending.deny(),
                OwnerAuthorization::Error(error) => Err(error),
            },
            AuthorizationResult::Failed(response) => Ok(response),
            AuthorizationResult::Error(err) => Err(err),
        }
    }

    fn from_fail(source: Result<Request::Response, Request::Error>) -> Self {
        match source {
            Ok(response) => AuthorizationResult::Failed(response),
            Err(error) => AuthorizationResult::Error(error),
        }
    }
}

impl<'a, Req: WebRequest> PendingAuthorization<'a, Req> {
    /// Denies the request, the client is not allowed access.
    pub fn deny(self) -> Result<Req::Response, Req::Error> {
        let authorization = self.request.deny();
        match authorization {
            Err(CodeError::Ignore)
                => return Err(OAuthError::DenySilently.into()),
            Err(CodeError::Redirect(url))
                => return Req::Response::redirect_error(ErrorRedirect(url)),
            Ok(redirect_to) => Req::Response::redirect(redirect_to),
       }
    }

    /// Postpones the decision over the request, to display data to the resource owner.
    ///
    /// This should happen at least once for each request unless the resource owner has already
    /// acknowledged and pre-approved a specific grant.  The response can also be used to determine
    /// the resource owner, if no login has been detected or if multiple accounts are allowed to
    /// be logged in at the same time.
    pub fn in_progress(self, response: Req::Response) -> Req::Response {
        response
    }

    /// Tells the system that the resource owner with the given id has approved the grant.
    pub fn authenticated(self, owner: String) -> Result<Req::Response, Req::Error> {
        let authorization = self.request.authorize(&self.primitives, owner.into());
        match authorization {
            Err(CodeError::Ignore)
                => return Err(OAuthError::DenySilently.into()),
            Err(CodeError::Redirect(url))
                => return Req::Response::redirect_error(ErrorRedirect(url)),
            Ok(redirect_to) => Req::Response::redirect(redirect_to),
        }
    }
}

impl<'a> AuthorizationPrimitives<'a> {
    fn new(registrar: &'a Registrar, authorizer: &'a mut Authorizer) -> Self {
        Self {
            registrar: Cell::new(registrar),
            authorizer: Cell::new(Some(authorizer)),
        }
    }
}

impl<'a> AuthorizationEndpoint for AuthorizationPrimitives<'a> {
    fn bound_redirect<'s>(&'s self, bound: ClientUrl<'s>) -> Result<BoundClient<'s>, RegistrarError> {
        self.registrar
            .get()
            .bound_redirect(bound)
    }

    fn authorize(&self, grant: Grant) -> Result<String, ()> {
        match self.authorizer.replace(None) {
            Some(authorizer) => authorizer.authorize(grant),
            None => unreachable!("This function should only be invoked once!"),
        }
    }
}

/// All relevant methods for granting access token from authorization codes.
pub struct GrantFlow<'a> {
    registrar: Cell<&'a Registrar>,
    authorizer: Cell<Option<&'a mut Authorizer>>,
    issuer: Cell<Option<&'a mut Issuer>>,
    extensions: Vec<&'a AccessTokenExtension>,
}

impl<'l> From<QueryParameter<'l>> for AccessTokenParameter<'l> {
    fn from(map: QueryParameter<'l>) -> AccessTokenParameter<'l> {
        AccessTokenParameter {
            valid: true,
            client_id: map.get("client_id"),
            code: map.get("code"),
            redirect_uri: map.get("redirect_uri"),
            grant_type: map.get("grant_type"),
            authorization: None,
            extensions: map,
        }
    }
}

impl<'l> AccessTokenRequest for AccessTokenParameter<'l> {
    fn valid(&self) -> bool {
        self.valid
    }

    fn code(&self) -> Option<Cow<str>> {
        self.code.clone()
    }

    fn client_id(&self) -> Option<Cow<str>> {
        self.client_id.clone()
    }

    fn redirect_uri(&self) -> Option<Cow<str>> {
        self.redirect_uri.clone()
    }

    fn grant_type(&self) -> Option<Cow<str>> {
        self.grant_type.clone()
    }

    fn authorization(&self) -> Option<(Cow<str>, Cow<[u8]>)> {
        match self.authorization {
            None => None,
            Some((ref id, ref pass))
                => Some((id.as_str().into(), pass.as_slice().into())),
        }
    }

    fn extension(&self, key: &str) -> Option<Cow<str>> {
        self.extensions.get(key)
    }
}

impl<'l> AccessTokenParameter<'l> {
    fn invalid() -> Self {
        AccessTokenParameter {
            valid: false,
            code: None,
            client_id: None,
            redirect_uri: None,
            grant_type: None,
            authorization: None,
            extensions: QueryParameter::SingleValue(
                SingleValueQuery::CowValue(
                    Cow::Owned(HashMap::new())
                )
            ),
        }
    }
}

impl<'a> GrantFlow<'a> {
    /// Initiate an access token flow.
    pub fn new(registrar: &'a Registrar, authorizer: &'a mut Authorizer, issuer: &'a mut Issuer) -> Self {
        GrantFlow {
            registrar: Cell::new(registrar),
            authorizer: Cell::new(Some(authorizer)),
            issuer: Cell::new(Some(issuer)),
            extensions: Vec::new(),
        }
    }

    /// Add an extension to access token handling.
    pub fn with_extension(mut self, extension: &'a AccessTokenExtension) -> Self {
        self.extensions.push(extension);
        self
    }

    fn create_valid_params<'w, W: WebRequest>(req: &'w mut W) -> Option<AccessTokenParameter<'w>> {
        let authorization = match req.authheader() {
            Err(_) => return None,
            Ok(None) => None,
            Ok(Some(ref header)) => {
                if !header.starts_with("Basic ") {
                    return None
                }

                let combined = match base64::decode(&header[6..]) {
                    Err(_) => return None,
                    Ok(vec) => vec,
                };

                let mut split = combined.splitn(2, |&c| c == b':');
                let client_bin = match split.next() {
                    None => return None,
                    Some(client) => client,
                };
                let passwd = match split.next() {
                    None => return None,
                    Some(passwd64) => passwd64,
                };

                let client = match from_utf8(client_bin) {
                    Err(_) => return None,
                    Ok(client) => client,
                };

                Some((client.to_string(), passwd.to_vec()))
            },
        };

        let mut params: AccessTokenParameter<'w> = match req.urlbody() {
            Err(_) => return None,
            Ok(body) => body.into(),
        };

        params.authorization = authorization;

        Some(params)
    }

    /// Construct a response containing the access token or an error message.
    pub fn handle<Req>(self, mut request: Req)
    -> Result<Req::Response, Req::Error> where Req: WebRequest
    {
        let params = GrantFlow::create_valid_params(&mut request)
            .unwrap_or(AccessTokenParameter::invalid());

        match access_token(&self, &params, self.extensions.as_slice()) {
            Err(IssuerError::Invalid(json_data))
                => return Req::Response::json(&json_data.to_json())?.as_client_error(),
            Err(IssuerError::Unauthorized(json_data, scheme))
                => return Req::Response::json(&json_data.to_json())?.as_unauthorized()?.with_authorization(&scheme),
            Err(IssuerError::Internal)
                => Err(OAuthError::PrimitiveError.into()),
            Ok(token) => Req::Response::json(&token.to_json()),
        }
    }
}

impl<'a> AccessTokenEndpoint for GrantFlow<'a> {
    fn client(&self, client_id: &str) -> Option<RegisteredClient> {
        self.registrar
            .get()
            .client(client_id)
    }

    fn extract(&self, code: &str) -> Option<Grant> {
        match self.authorizer.replace(None) {
            Some(authorizer) => authorizer.extract(code),
            None => unreachable!("This function should only be invoked once!"),
        }
    }

    fn issue(&self, grant: Grant) -> Result<IssuedToken, ()> {
        match self.issuer.replace(None) {
            Some(issuer) => issuer.issue(grant),
            None => unreachable!("This function should only be invoked once!"),
        }
    }
}

/// All relevant methods for checking authorization for access to a resource.
pub struct AccessFlow<'a> {
    issuer: Cell<Option<&'a mut Issuer>>,
    scopes: &'a [Scope],
}

impl<'l> GuardRequest for GuardParameter<'l> {
    fn valid(&self) -> bool {
        self.valid
    }

    fn token(&self) -> Option<Cow<str>> {
        self.token.clone()
    }
}

impl<'l> GuardParameter<'l> {
    fn invalid() -> Self {
        GuardParameter {
            valid: false,
            token: None
        }
    }
}

impl<'a> AccessFlow<'a> {
    /// Initiate an access to a protected resource
    pub fn new(issuer: &'a mut Issuer, scopes: &'a [Scope]) -> Self {
        AccessFlow {
            issuer: Cell::new(Some(issuer)),
            scopes,
        }
    }

    fn create_valid_params<W: WebRequest>(req: &mut W) -> Option<GuardParameter> {
        let token = match req.authheader() {
            Err(_) => return None,
            Ok(None) => None,
            Ok(Some(header)) => {
                if !header.starts_with("Bearer ") {
                    return None
                }

                match header {
                    Cow::Borrowed(v) => Some(Cow::Borrowed(&v[7..])),
                    Cow::Owned(v) => Some(Cow::Owned(v[7..].to_string())),
                }
            }
        };

        Some(GuardParameter { valid: true, token })
    }

    /// Indicate if the access is allowed or denied via a result.
    pub fn handle<R>(&self, mut request: R)
    -> Result<(), R::Error> where R: WebRequest {
        let params = AccessFlow::create_valid_params(&mut request)
            .unwrap_or_else(|| GuardParameter::invalid());

        protect(self, &params).map_err(|error| OAuthError::AccessDenied {
            error,
        }).map_err(Into::into)
    }
}

impl<'a> GuardEndpoint for AccessFlow<'a> {
    fn scopes(&self) -> &[Scope] {
        self.scopes
    }

    fn recover_token(&self, id: &str) -> Option<Grant> {
        match self.issuer.replace(None) {
            Some(issuer) => issuer.recover_token(id),
            None => unreachable!("This function should only be invoked once!"),
        }
    }
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
        error: AccessError,
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
