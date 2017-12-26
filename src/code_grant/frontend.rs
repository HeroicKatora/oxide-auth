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
use std::borrow::Cow;
use std::collections::HashMap;
use std::error;
use std::fmt;
use std::marker::PhantomData;
use std::str::from_utf8;

use primitives::registrar::PreGrant;
use super::backend::{AccessTokenRequest, CodeRef, CodeRequest, CodeError, ErrorUrl, IssuerError, IssuerRef};
use super::backend::{AccessError, GuardRequest, GuardRef};
use url::Url;
use base64;

/// Holds the decode query fragments from the url. This does not hold the excess parameters with a
/// Cow, as we need to have a mutable reference to it for the authorization handler.
struct AuthorizationParameter {
    valid: bool,
    method: Option<String>,
    client_id: Option<String>,
    scope: Option<String>,
    redirect_url: Option<String>,
    state: Option<String>,
}

/// Answer from OwnerAuthorizer to indicate the owners choice.
#[derive(Clone)]
pub enum Authentication {
    Failed,
    InProgress,
    Authenticated(String),
}

struct AccessTokenParameter<'a> {
    valid: bool,
    client_id: Option<Cow<'a, str>>,
    redirect_url: Option<Cow<'a, str>>,
    grant_type: Option<Cow<'a, str>>,
    code: Option<Cow<'a, str>>,
    authorization: Option<(String, Vec<u8>)>,
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

pub trait OwnerAuthorizer {
    type Request: WebRequest;
    fn get_owner_authorization(&self, &mut Self::Request, &PreGrant)
      -> Result<(Authentication, <Self::Request as WebRequest>::Response), <Self::Request as WebRequest>::Error>;
}

pub struct AuthorizationFlow;
pub struct PreparedAuthorization<'l, Req> where
    Req: WebRequest + 'l,
{
    request: &'l mut Req,
    urldecoded: AuthorizationParameter,
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

impl<'l> From<HashMap<Cow<'l, str>, Cow<'l, str>>> for AuthorizationParameter {
    fn from(mut val: HashMap<Cow<'l, str>, Cow<'l, str>>) -> Self {
        AuthorizationParameter {
            valid: true,
            client_id: val.remove("client_id").map(|v| v.into_owned()),
            scope: val.remove("scope").map(|v| v.into_owned()),
            redirect_url: val.remove("redirect_uri").map(|v| v.into_owned()),
            state: val.remove("state").map(|v| v.into_owned()),
            method: val.remove("response_type").map(|v| v.into_owned()),
        }
    }
}

impl CodeRequest for AuthorizationParameter {
    fn valid(&self) -> bool { self.valid }
    fn client_id(&self) -> Option<Cow<str>> { self.client_id.as_ref().map(|c| c.as_str().into()) }
    fn scope(&self) -> Option<Cow<str>> { self.scope.as_ref().map(|c| c.as_str().into()) }
    fn redirect_url(&self) -> Option<Cow<str>> { self.redirect_url.as_ref().map(|c| c.as_str().into()) }
    fn state(&self) -> Option<Cow<str>> { self.state.as_ref().map(|c| c.as_str().into()) }
    fn method(&self) -> Option<Cow<str>> { self.method.as_ref().map(|c| c.as_str().into()) }
}

impl AuthorizationParameter {
    fn invalid() -> Self {
        AuthorizationParameter { valid: false, method: None, client_id: None, scope: None,
            redirect_url: None, state: None }
    }
}

impl AuthorizationFlow {
    /// Idempotent data processing, checks formats.
    pub fn prepare<W: WebRequest>(incoming: &mut W) -> Result<PreparedAuthorization<W>, W::Error> {
        let urldecoded = incoming.query()
            .map(extract_single_parameters)
            .map(|map| map.into())
            .unwrap_or_else(|_| AuthorizationParameter::invalid());

        Ok(PreparedAuthorization{request: incoming, urldecoded})
    }

    pub fn handle<'c, Req>(granter: CodeRef<'c>, prepared: PreparedAuthorization<'c, Req>, page_handler: &OwnerAuthorizer<Request=Req>)
    -> Result<Req::Response, Req::Error> where
        Req: WebRequest,
    {
        let PreparedAuthorization { request: req, urldecoded } = prepared;
        let negotiated = match granter.negotiate(&urldecoded) {
            Err(CodeError::Ignore) => return Err(OAuthError::InternalCodeError().into()),
            Err(CodeError::Redirect(url)) => return Req::Response::redirect_error(url),
            Ok(v) => v,
        };

        let authorization = match page_handler.get_owner_authorization(req, negotiated.pre_grant())? {
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

pub struct GrantFlow;
pub struct PreparedGrant<'l, Req> where
    Req: WebRequest + 'l,
{
    params: AccessTokenParameter<'l>,
    req: PhantomData<Req>,
}

impl<'l> From<HashMap<Cow<'l, str>, Cow<'l, str>>> for AccessTokenParameter<'l> {
    fn from(mut map: HashMap<Cow<'l, str>, Cow<'l, str>>) -> AccessTokenParameter<'l> {
        AccessTokenParameter {
            valid: true,
            client_id: map.remove("client_id"),
            code: map.remove("code"),
            redirect_url: map.remove("redirect_uri"),
            grant_type: map.remove("grant_type"),
            authorization: None,
        }
    }
}

impl<'l> AccessTokenRequest for AccessTokenParameter<'l> {
    fn valid(&self) -> bool { self.valid }
    fn code(&self) -> Option<Cow<str>> { self.code.clone() }
    fn client_id(&self) -> Option<Cow<str>> { self.client_id.clone() }
    fn redirect_url(&self) -> Option<Cow<str>> { self.redirect_url.clone() }
    fn grant_type(&self) -> Option<Cow<str>> { self.grant_type.clone() }
    fn authorization(&self) -> Option<(Cow<str>, Cow<[u8]>)> {
        match self.authorization {
            None => None,
            Some((ref id, ref pass))
                => Some((id.as_str().into(), pass.as_slice().into())),
        }
    }
}

impl<'l> AccessTokenParameter<'l> {
    fn invalid() -> Self {
        AccessTokenParameter { valid: false, code: None, client_id: None, redirect_url: None,
            grant_type: None, authorization: None }
    }
}

impl GrantFlow {
    pub fn prepare<W: WebRequest>(req: &mut W) -> Result<PreparedGrant<W>, W::Error> {
        let params = GrantFlow::create_valid_params(req)
            .unwrap_or(AccessTokenParameter::invalid());
        Ok(PreparedGrant { params: params, req: PhantomData })
    }

    fn create_valid_params<'a, W: WebRequest>(req: &'a mut W) -> Option<AccessTokenParameter<'a>> {
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

        let mut params: AccessTokenParameter<'a> = match req.urlbody() {
            Err(_) => return None,
            Ok(body) => extract_single_parameters(body).into(),
        };

        params.authorization = authorization;

        Some(params)
    }

    pub fn handle<Req>(mut issuer: IssuerRef, prepared: PreparedGrant<Req>)
    -> Result<Req::Response, Req::Error> where Req: WebRequest
    {
        let PreparedGrant { params, .. } = prepared;
        match issuer.use_code(&params) {
            Err(IssuerError::Invalid(json_data))
                => return Req::Response::json(&json_data.to_json())?.as_client_error(),
            Err(IssuerError::Unauthorized(json_data, scheme))
                => return Req::Response::json(&json_data.to_json())?.as_unauthorized()?.with_authorization(&scheme),
            Ok(token) => Req::Response::json(&token.to_json()),
        }
    }
}

pub struct AccessFlow;
pub struct PreparedAccess<'l, Req> where
    Req: WebRequest + 'l,
{
    params: GuardParameter<'l>,
    req: PhantomData<Req>,
}

impl<'l> GuardRequest for GuardParameter<'l> {
    fn valid(&self) -> bool { self.valid }
    fn token(&self) -> Option<Cow<str>> { self.token.clone() }
}

impl<'l> GuardParameter<'l> {
    fn invalid() -> Self {
        GuardParameter { valid: false, token: None }
    }
}

impl AccessFlow {
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

    pub fn prepare<W: WebRequest>(req: &mut W) -> Result<PreparedAccess<W>, W::Error> {
        let params = AccessFlow::create_valid_params(req)
            .unwrap_or_else(|| GuardParameter::invalid());

        Ok(PreparedAccess { params: params, req: PhantomData })
    }

    pub fn handle<Req>(guard: GuardRef, prepared: PreparedAccess<Req>)
    -> Result<(), Req::Error> where Req: WebRequest {
        guard.protect(&prepared.params).map_err(|err| {
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
    InternalCodeError(),
    InternalAccessError(),
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
