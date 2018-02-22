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
//! use oxide_auth::code_grant::frontend::{WebRequest, WebResponse, OAuthError};
//! use oxide_auth::code_grant::frontend::{IssuerRef, GrantFlow};
//! use oxide_auth::primitives::prelude::*;
//! use url::Url;
//! struct MyRequest { /* user defined */ }
//! struct MyResponse { /* user defined */ }
//!
//! impl WebRequest for MyRequest {
//!     type Error = OAuthError; /* Custom type permitted but this is easier */
//!     type Response = MyResponse;
//!     /* Implementation of the traits' methods */
//! # fn query(&mut self) -> Result<Cow<HashMap<String, Vec<String>>>, ()> { Err(()) }
//! # fn urlbody(&mut self) -> Result<Cow<HashMap<String, Vec<String>>>, ()> { Err(()) }
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
//! fn handle(state: State, request: &mut MyRequest) -> Result<MyResponse, OAuthError> {
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
use std::collections::HashMap;
use std::error;
use std::fmt;
use std::str::from_utf8;

use primitives::authorizer::Authorizer;
use primitives::issuer::Issuer;
use primitives::registrar::{Registrar, PreGrant};
use primitives::scope::Scope;
use super::backend::{AccessTokenRequest, CodeRequest, CodeError, IssuerError};
use super::backend::{AccessError, GuardRequest};
use super::extensions::{AccessTokenExtension, CodeExtension};

pub use super::backend::{CodeRef, ErrorUrl, IssuerRef, GuardRef};

use url::Url;
use base64;

/// Holds the decode query fragments from the url. This does not hold the excess parameters with a
/// Cow, as we need to have a mutable reference to it for the authorization handler.
struct AuthorizationParameter<'a> {
    valid: bool,
    method: Option<Cow<'a, str>>,
    client_id: Option<Cow<'a, str>>,
    scope: Option<Cow<'a, str>>,
    redirect_uri: Option<Cow<'a, str>>,
    state: Option<Cow<'a, str>>,
    extensions: HashMap<Cow<'a, str>, Cow<'a, str>>,
}

/// Answer from OwnerAuthorizer to indicate the owners choice.
#[derive(Clone)]
pub enum Authentication {
    /// The owner did not authorize the client.
    Failed,

    /// The owner has not yet decided, i.e. the returned page is a form for the user.
    InProgress,

    /// Authorization was granted by the specified user.
    Authenticated(String),
}

struct AccessTokenParameter<'a> {
    valid: bool,
    client_id: Option<Cow<'a, str>>,
    redirect_uri: Option<Cow<'a, str>>,
    grant_type: Option<Cow<'a, str>>,
    code: Option<Cow<'a, str>>,
    authorization: Option<(String, Vec<u8>)>,
    extensions: HashMap<Cow<'a, str>, Cow<'a, str>>,
}

struct GuardParameter<'a> {
    valid: bool,
    token: Option<Cow<'a, str>>,
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
    fn query(&mut self) -> Result<Cow<HashMap<String, Vec<String>>>, ()>;

    /// Retriev the parsed `application/x-form-urlencoded` body of the request. An Err value
    /// indicates a malformed body or a different Content-Type.
    fn urlbody(&mut self) -> Result<Cow<HashMap<String, Vec<String>>>, ()>;

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
    fn redirect_error(target: ErrorUrl) -> Result<Self, Self::Error> {
        Self::redirect(target.into())
    }

    /// Set the response status to 400
    fn as_client_error(self) -> Result<Self, Self::Error>;
    /// Set the response status to 401
    fn as_unauthorized(self) -> Result<Self, Self::Error>;
    /// Add an Authorization header
    fn with_authorization(self, kind: &str) -> Result<Self, Self::Error>;
}

/// Some instance which can decide the owners approval based on the request.
pub trait OwnerAuthorizer<Request: WebRequest> {
    /// Has the owner granted authorization to the client indicated in the `PreGrant`?
    fn get_owner_authorization(&self, &mut Request, &PreGrant)
      -> Result<(Authentication, <Request as WebRequest>::Response), <Request as WebRequest>::Error>;
}

fn extract_single_parameters<'l>(params: Cow<'l, HashMap<String, Vec<String>>>)
 -> HashMap<Cow<'l, str>, Cow<'l, str>> {
    match params {
        Cow::Owned(map) => map.into_iter()
            .filter_map(|(k, mut v)|
                if v.len() < 2 {
                    v.pop().map(|v| (k, v))
                } else { None })
            .map(|(k, v)| (k.into(), v.into()))
            .collect::<HashMap<_, _>>(),
        Cow::Borrowed(map) => map.iter()
           .filter_map(|(ref k, ref v)|
                if v.len() == 1 {
                    Some((k.as_str().into(), v[0].as_str().into()))
                } else { None })
           .collect::<HashMap<_, _>>(),
    }
}

impl<'l, W: WebRequest> From<&'l mut W> for AuthorizationParameter<'l> {
    fn from(val: &'l mut W) -> Self {
        let mut params = match val.query() {
            Err(()) => return Self::invalid(),
            Ok(query) => extract_single_parameters(query),
        };

        AuthorizationParameter {
            valid: true,
            client_id: params.remove("client_id"),
            scope: params.remove("scope"),
            redirect_uri: params.remove("redirect_uri"),
            state: params.remove("state"),
            method: params.remove("response_type"),
            extensions: params,
        }
    }
}

impl<'l> CodeRequest for AuthorizationParameter<'l> {
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
        self.extensions.get(key).cloned()
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
            extensions: HashMap::new()
        }
    }
}

/// All relevant methods for handling authorization code requests.
pub struct AuthorizationFlow<'a> {
    backend: CodeRef<'a>,
    extensions: Vec<&'a CodeExtension>,
}

impl<'a> AuthorizationFlow<'a> {
    /// Initiate an authorization code token flow.
    pub fn new(registrar: &'a Registrar, authorizer: &'a mut Authorizer) -> Self {
        AuthorizationFlow {
            backend: CodeRef::with(registrar, authorizer),
            extensions: Vec::new(),
        }
    }

    /// Add an extension to access token handling.
    pub fn with_extension(mut self, extension: &'a CodeExtension) -> Self {
        self.extensions.push(extension);
        self
    }

    /// React to an authorization code request, handling owner approval with a specified handler.
    pub fn handle<Req>(self, mut request: Req, page_handler: &OwnerAuthorizer<Req>)
    -> Result<Req::Response, Req::Error> where
        Req: WebRequest,
    {
        let negotiated = {
            let urldecoded = AuthorizationParameter::from(&mut request);
            let negotiated = match self.backend.negotiate(&urldecoded, self.extensions.as_slice()) {
                Err(CodeError::Ignore) => return Err(OAuthError::InternalCodeError().into()),
                Err(CodeError::Redirect(url)) => return Req::Response::redirect_error(url),
                Ok(v) => v,
            };

            negotiated
        };

        let authorization = match page_handler.get_owner_authorization(&mut request, negotiated.pre_grant())? {
            (Authentication::Failed, _)
                => negotiated.deny(),
            (Authentication::InProgress, response)
                => return Ok(response),
            (Authentication::Authenticated(owner), _)
                => negotiated.authorize(owner.into()),
        };

        let redirect_to = match authorization {
           Err(CodeError::Ignore) => return Err(OAuthError::InternalCodeError().into()),
           Err(CodeError::Redirect(url)) => return Req::Response::redirect_error(url),
           Ok(v) => v,
       };

        Req::Response::redirect(redirect_to)
    }
}

/// All relevant methods for granting access token from authorization codes.
pub struct GrantFlow<'a> {
    backend: IssuerRef<'a>,
    extensions: Vec<&'a AccessTokenExtension>,
}

impl<'l> From<HashMap<Cow<'l, str>, Cow<'l, str>>> for AccessTokenParameter<'l> {
    fn from(mut map: HashMap<Cow<'l, str>, Cow<'l, str>>) -> AccessTokenParameter<'l> {
        AccessTokenParameter {
            valid: true,
            client_id: map.remove("client_id"),
            code: map.remove("code"),
            redirect_uri: map.remove("redirect_uri"),
            grant_type: map.remove("grant_type"),
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
        self.extensions.get(key).cloned()
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
            extensions: HashMap::new(),
        }
    }
}

impl<'a> GrantFlow<'a> {
    /// Initiate an access token flow.
    pub fn new(registrar: &'a Registrar, authorizer: &'a mut Authorizer, issuer: &'a mut Issuer) -> Self {
        GrantFlow {
            backend: IssuerRef::with(registrar, authorizer, issuer),
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
            Ok(body) => extract_single_parameters(body).into(),
        };

        params.authorization = authorization;

        Some(params)
    }

    /// Construct a response containing the access token or an error message.
    pub fn handle<Req>(mut self, mut request: Req)
    -> Result<Req::Response, Req::Error> where Req: WebRequest
    {
        let params = GrantFlow::create_valid_params(&mut request)
            .unwrap_or(AccessTokenParameter::invalid());

        match self.backend.use_code(&params, self.extensions.as_slice()) {
            Err(IssuerError::Invalid(json_data))
                => return Req::Response::json(&json_data.to_json())?.as_client_error(),
            Err(IssuerError::Unauthorized(json_data, scheme))
                => return Req::Response::json(&json_data.to_json())?.as_unauthorized()?.with_authorization(&scheme),
            Ok(token) => Req::Response::json(&token.to_json()),
        }
    }
}

/// All relevant methods for checking authorization for access to a resource.
pub struct AccessFlow<'a> {
    backend: GuardRef<'a>,
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
            backend: GuardRef::with(issuer, scopes)
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

        self.backend.protect(&params).map_err(|err| {
            match err {
                AccessError::InvalidRequest => OAuthError::InternalAccessError(),
                AccessError::AccessDenied => OAuthError::AccessDenied,
            }.into()
        })
    }
}

/// Errors which should not or need not be communicated to the requesting party but which are of
/// interest to the server. See the documentation for each enum variant for more documentation on
/// each as some may have an expected response. These include badly formatted headers or url encoded
/// body, unexpected parameters, or security relevant required parameters.
#[derive(Debug)]
pub enum OAuthError {
    /// Some unexpected, internal error occured-
    InternalCodeError(),

    /// Access should be silently denied, without providing further explanation.
    ///
    /// For example, this response is given when an incorrect client has been provided in the
    /// authorization request in order to avoid potential indirect denial of service vulnerabilities.
    InternalAccessError(),

    /// No authorization has been granted.
    AccessDenied,
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
