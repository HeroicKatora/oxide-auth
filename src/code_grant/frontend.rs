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
use super::backend::{CodeRef, CodeRequest, CodeError, ErrorUrl, IssuerRef};
use url::Url;
use serde_json;

/// Holds the decode query fragments from the url
struct ClientParameter<'a> {
    pub client_id: Option<Cow<'a, str>>,
    pub scope: Option<Cow<'a, str>>,
    pub redirect_url: Option<Cow<'a, str>>,
    pub state: Option<Cow<'a, str>>,
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

pub trait WebRequest {
    type Response: WebResponse;
    fn query(&mut self) -> Option<HashMap<String, Vec<String>>>;
    fn urlbody(&mut self) -> Option<&HashMap<String, Vec<String>>>;
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

fn extract_parameters(params: HashMap<String, Vec<String>>) -> Result<ClientParameter<'static>, String> {
    let map = params.iter()
        .filter(|&(_, v)| v.len() == 1)
        .map(|(k, v)| (k.as_str(), v[0].as_str()))
        .collect::<HashMap<&str, &str>>();

    Ok(ClientParameter{
        client_id: map.get("client_id").map(|client| client.to_string().into()),
        scope: map.get("scope").map(|scope| scope.to_string().into()),
        redirect_url: map.get("redirect_url").map(|url| url.to_string().into()),
        state: map.get("state").map(|state| state.to_string().into()),
    })
}

impl<'s> CodeRequest for ClientParameter<'s> {
    fn client_id(&self) -> Option<Cow<str>> { self.client_id.as_ref().map(|c| c.as_ref().into()) }
    fn scope(&self) -> Option<Cow<str>> { self.scope.as_ref().map(|c| c.as_ref().into()) }
    fn redirect_url(&self) -> Option<Cow<str>> { self.redirect_url.as_ref().map(|c| c.as_ref().into()) }
    fn state(&self) -> Option<Cow<str>> { self.state.as_ref().map(|c| c.as_ref().into()) }
}

impl AuthorizationFlow {
    /// Idempotent data processing, checks formats.
    pub fn prepare<W: WebRequest>(incoming: &mut W) -> Result<PreparedAuthorization<W>, OAuthError> {
        let urlparameters = match incoming.query() {
            None => return Err(OAuthError::MissingQuery),
            Some(res) => res,
        };

        let urldecoded = match extract_parameters(urlparameters) {
            Err(st) => return Err(OAuthError::BadRequest(st)),
            Ok(url) => url,
        };

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
    client: &'l str,
    code: &'l str,
    redirect_url: &'l str,
    req: PhantomData<Req>,
}

impl GrantFlow {
    pub fn prepare<W: WebRequest>(req: &mut W) -> Result<PreparedGrant<W>, OAuthError> {
        use std::borrow::Cow;
        let (client, code, redirect_url) = {
            let query = match req.urlbody() {
                None => return Err(OAuthError::BadRequest("Invalid url encoded body".to_string())),
                Some(v) => v,
            };

            fn single_result<'l>(list: &'l Vec<String>) -> Result<&'l str, Cow<'static, str>>{
                if list.len() == 1 { Ok(&list[0]) } else { Err("Invalid parameter".into()) }
            }
            let get_param = |name: &str| query.get(name).ok_or(Cow::Owned("Missing parameter".to_owned() + name)).and_then(single_result);

            let grant_typev = get_param("grant_type").and_then(
                |grant| if grant == "authorization_code" { Ok(grant) } else { Err(Cow::Owned("Invalid grant type".to_owned() + grant)) });
            let client_idv = get_param("client_id");
            let codev = get_param("code");
            let redirect_urlv = get_param("redirect_url");

            match (grant_typev, client_idv, codev, redirect_urlv) {
                (Err(cause), _, _, _) => return Err(OAuthError::BadRequest(cause.into_owned())),
                (_, Err(cause), _, _) => return Err(OAuthError::BadRequest(cause.into_owned())),
                (_, _, Err(cause), _) => return Err(OAuthError::BadRequest(cause.into_owned())),
                (_, _, _, Err(cause)) => return Err(OAuthError::BadRequest(cause.into_owned())),
                (Ok(_), Ok(client), Ok(code), Ok(redirect))
                    => (client, code, redirect)
            }
        };
        Ok(PreparedGrant { client, code, redirect_url, req: PhantomData })
    }

    pub fn handle<Req>(mut issuer: IssuerRef, prepared: PreparedGrant<Req>) -> Result<<Req as WebRequest>::Response, OAuthError> where
        Req: WebRequest
    {
        let PreparedGrant { code, client, redirect_url, .. } = prepared;
        let token = match issuer.use_code(code.to_string(), client.into(), redirect_url.into()) {
            Err(json_data) => return Req::Response::json(&json_data.to_json()),
            Ok(token) => token,
        };

        let serialized = serde_json::to_string(&[
                ("token", token.token.as_str()),
                ("refresh", token.refresh.as_str()),
            ].iter().cloned().collect::<HashMap<_, _>>())
            .unwrap(); // We control the input, this is valid json

        Req::Response::json(&serialized)
    }
}

pub enum OAuthError {
    MissingQuery,
    BadRequest(String),
    AuthenticationFailed,
    Other(String),
}
