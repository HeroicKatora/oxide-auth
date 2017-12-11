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
use std::marker::PhantomData;
use std::fmt;
use std::error;
use primitives::registrar::PreGrant;
use super::backend::{AccessTokenRequest, CodeRef, CodeRequest, CodeError, ErrorUrl, IssuerError, IssuerRef};
use super::backend::{AccessError, GuardRequest, GuardRef};
use url::Url;
use base64;

/// Holds the decode query fragments from the url
struct AuthorizationParameter<'a> {
    valid: bool,
    method: Option<Cow<'a, str>>,
    client_id: Option<Cow<'a, str>>,
    scope: Option<Cow<'a, str>>,
    redirect_url: Option<Cow<'a, str>>,
    state: Option<Cow<'a, str>>,
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
    fn query(&mut self) -> Result<HashMap<String, Vec<String>>, ()>;
    /// Retriev the parsed `application/x-form-urlencoded` body of the request. An Err value
    /// indicates a malformed body or a different Content-Type.
    fn urlbody(&mut self) -> Result<&HashMap<String, Vec<String>>, ()>;
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
    urldecoded: AuthorizationParameter<'l>,
}

fn extract_parameters(params: HashMap<String, Vec<String>>) -> AuthorizationParameter<'static> {
    let map = params.iter()
        .filter(|&(_, v)| v.len() == 1)
        .map(|(k, v)| (k.as_str(), v[0].as_str()))
        .collect::<HashMap<&str, &str>>();

    AuthorizationParameter{
        valid: true,
        method: map.get("response_type").map(|method| method.to_string().into()),
        client_id: map.get("client_id").map(|client| client.to_string().into()),
        scope: map.get("scope").map(|scope| scope.to_string().into()),
        redirect_url: map.get("redirect_url").map(|url| url.to_string().into()),
        state: map.get("state").map(|state| state.to_string().into()),
    }
}

impl<'s> CodeRequest for AuthorizationParameter<'s> {
    fn valid(&self) -> bool { self.valid }
    fn client_id(&self) -> Option<Cow<str>> { self.client_id.as_ref().map(|c| c.as_ref().into()) }
    fn scope(&self) -> Option<Cow<str>> { self.scope.as_ref().map(|c| c.as_ref().into()) }
    fn redirect_url(&self) -> Option<Cow<str>> { self.redirect_url.as_ref().map(|c| c.as_ref().into()) }
    fn state(&self) -> Option<Cow<str>> { self.state.as_ref().map(|c| c.as_ref().into()) }
    fn method(&self) -> Option<Cow<str>> { self.method.as_ref().map(|c| c.as_ref().into()) }
}

impl<'s> AuthorizationParameter<'s> {
    fn invalid() -> Self {
        AuthorizationParameter { valid: false, method: None, client_id: None, scope: None,
            redirect_url: None, state: None }
    }
}

impl AuthorizationFlow {
    /// Idempotent data processing, checks formats.
    pub fn prepare<W: WebRequest>(incoming: &mut W) -> Result<PreparedAuthorization<W>, W::Error> {
        let urldecoded = incoming.query()
            .map(extract_parameters)
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

fn extract_access_token<'l>(params: &'l HashMap<String, Vec<String>>) -> AccessTokenParameter<'l> {
    let map = params.iter()
        .filter(|&(_, v)| v.len() == 1)
        .map(|(k, v)| (k.as_str(), v[0].as_str()))
        .collect::<HashMap<_, _>>();

    AccessTokenParameter {
        valid: true,
        client_id: map.get("client_id").map(|v| (*v).into()),
        code: map.get("code").map(|v| (*v).into()),
        redirect_url: map.get("redirect_url").map(|v| (*v).into()),
        grant_type: map.get("grant_type").map(|v| (*v).into()),
        authorization: None,
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

                let mut split =  header[6..].splitn(2, ':');
                let client = match split.next() {
                    None => return None,
                    Some(client) => client,
                };
                let passwd64 = match split.next() {
                    None => return None,
                    Some(passwd64) => passwd64,
                };
                let passwd = match base64::decode(&passwd64) {
                    Err(_) => return None,
                    Ok(vec) => vec,
                };

                Some((client.to_string(), passwd))
            },
        };

        let mut params = match req.urlbody() {
            Err(_) => return None,
            Ok(body) => extract_access_token(body),
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
