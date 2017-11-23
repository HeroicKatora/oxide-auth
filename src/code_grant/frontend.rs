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
use super::backend::{AccessTokenRequest, CodeRef, CodeRequest, CodeError, ErrorUrl, IssuerError, IssuerRef};
use url::Url;

/// Holds the decode query fragments from the url
struct ClientParameter<'a> {
    valid: bool,
    client_id: Option<Cow<'a, str>>,
    scope: Option<Cow<'a, str>>,
    redirect_url: Option<Cow<'a, str>>,
    state: Option<Cow<'a, str>>,
}

/// Sent to the OwnerAuthorizer to request owner permission.
pub struct AuthenticationRequest {
    pub client_id: String,
    pub scope: String,
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
}

pub trait WebRequest {
    type Response: WebResponse;
    /// Retrieve a parsed version of the url query. An Err return value indicates a malformed query
    /// or an otherwise malformed WebRequest. Note that an empty query should result in
    /// `Ok(HashMap::new())` instead of an Err.
    fn query(&mut self) -> Result<HashMap<String, Vec<String>>, ()>;
    /// Retriev the parsed `application/x-form-urlencoded` body of the request. An Err value
    /// indicates a malformed body or a different Content-Type.
    fn urlbody(&mut self) -> Result<&HashMap<String, Vec<String>>, ()>;
}

pub trait WebResponse where Self: Sized {
    fn redirect(url: Url) -> Result<Self, OAuthError>;
    fn text(text: &str) -> Result<Self, OAuthError>;
    fn json(data: &str) -> Result<Self, OAuthError>;

    /// Construct a redirect for the error. Here the response may choose to augment the error with
    /// additional information (such as help websites, description strings), hence the default
    /// implementation which does not do any of that.
    fn redirect_error(target: ErrorUrl) -> Result<Self, OAuthError> {
        Self::redirect(target.into())
    }

    /// Set the response status to 400
    fn as_client_error(self) -> Result<Self, OAuthError>;
    /// Set the response status to 401
    fn as_unauthorized(self) -> Result<Self, OAuthError>;
    /// Add an Authorization header
    fn with_authorization(self, kind: &str) -> Result<Self, OAuthError>;
}

pub trait OwnerAuthorizer {
    type Request: WebRequest;
    fn get_owner_authorization(&self, &mut Self::Request, AuthenticationRequest) -> Result<(Authentication, <Self::Request as WebRequest>::Response), OAuthError>;
}

pub struct AuthorizationFlow;
pub struct PreparedAuthorization<'l, Req> where
    Req: WebRequest + 'l,
{
    request: &'l mut Req,
    urldecoded: ClientParameter<'l>,
}

fn extract_parameters(params: HashMap<String, Vec<String>>) -> ClientParameter<'static> {
    let map = params.iter()
        .filter(|&(_, v)| v.len() == 1)
        .map(|(k, v)| (k.as_str(), v[0].as_str()))
        .collect::<HashMap<&str, &str>>();

    ClientParameter{
        valid: true,
        client_id: map.get("client_id").map(|client| client.to_string().into()),
        scope: map.get("scope").map(|scope| scope.to_string().into()),
        redirect_url: map.get("redirect_url").map(|url| url.to_string().into()),
        state: map.get("state").map(|state| state.to_string().into()),
    }
}

impl<'s> CodeRequest for ClientParameter<'s> {
    fn valid(&self) -> bool { self.valid }
    fn client_id(&self) -> Option<Cow<str>> { self.client_id.as_ref().map(|c| c.as_ref().into()) }
    fn scope(&self) -> Option<Cow<str>> { self.scope.as_ref().map(|c| c.as_ref().into()) }
    fn redirect_url(&self) -> Option<Cow<str>> { self.redirect_url.as_ref().map(|c| c.as_ref().into()) }
    fn state(&self) -> Option<Cow<str>> { self.state.as_ref().map(|c| c.as_ref().into()) }
}

impl<'s> ClientParameter<'s> {
    fn invalid() -> Self {
        ClientParameter { valid: false, client_id: None, scope: None,
            redirect_url: None, state: None }
    }
}

impl AuthorizationFlow {
    /// Idempotent data processing, checks formats.
    pub fn prepare<W: WebRequest>(incoming: &mut W) -> Result<PreparedAuthorization<W>, OAuthError> {
        let urldecoded = incoming.query()
            .map(extract_parameters)
            .unwrap_or_else(|_| ClientParameter::invalid());

        Ok(PreparedAuthorization{request: incoming, urldecoded})
    }

    pub fn handle<'c, Req, Auth>(granter: CodeRef<'c>, prepared: PreparedAuthorization<'c, Req>, page_handler: &Auth)
    -> Result<<Req as WebRequest>::Response, OAuthError> where
        Req: WebRequest,
        Auth: OwnerAuthorizer<Request=Req>
    {
        let PreparedAuthorization { request: req, urldecoded } = prepared;
        let negotiated = match granter.negotiate(&urldecoded) {
            Err(CodeError::Ignore) => return Err(OAuthError::BadRequest("Internal server error".to_string())),
            Err(CodeError::Redirect(url)) => return Req::Response::redirect_error(url),
            Ok(v) => v,
        };

        let auth = AuthenticationRequest{
            client_id: negotiated.negotiated().client_id.to_string(),
            scope: negotiated.negotiated().scope.to_string(),
        };

        let authorization = match page_handler.get_owner_authorization(req, auth)? {
            (Authentication::Failed, _)
                => negotiated.deny(),
            (Authentication::InProgress, response)
                => return Ok(response),
            (Authentication::Authenticated(owner), _)
                => negotiated.authorize(owner.into()),
        };

        let redirect_to = match authorization {
           Err(CodeError::Ignore) => return Err(OAuthError::BadRequest("Internal server error".to_string())),
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
    }
}

impl<'l> AccessTokenRequest for AccessTokenParameter<'l> {
    fn valid(&self) -> bool { self.valid }
    fn code(&self) -> Option<Cow<str>> { self.code.clone() }
    fn client_id(&self) -> Option<Cow<str>> { self.client_id.clone() }
    fn redirect_url(&self) -> Option<Cow<str>> { self.redirect_url.clone() }
    fn grant_type(&self) -> Option<Cow<str>> { self.grant_type.clone() }
    fn authorization(&self) -> Option<(Cow<str>, Cow<str>)> { None }
}

impl<'l> AccessTokenParameter<'l> {
    fn invalid() -> Self {
        AccessTokenParameter { valid: false, code: None, client_id: None, redirect_url: None,
            grant_type: None, }
    }
}

impl GrantFlow {
    pub fn prepare<W: WebRequest>(req: &mut W) -> Result<PreparedGrant<W>, OAuthError> {
        let params = req.urlbody()
            .map(extract_access_token)
            .unwrap_or_else(|_| AccessTokenParameter::invalid());

        Ok(PreparedGrant { params: params, req: PhantomData })
    }

    pub fn handle<Req>(mut issuer: IssuerRef, prepared: PreparedGrant<Req>) -> Result<<Req as WebRequest>::Response, OAuthError> where
        Req: WebRequest
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

pub enum OAuthError {
    MissingQuery,
    BadRequest(String),
    AuthenticationFailed,
    Other(String),
}
