//! General algorithms for frontends.
//!
//! To ensure the adherence to the oauth2 rfc and the improve general implementations, the control
//! flow of incoming packets is specified here instead of the frontend implementations.
//! Instead, traits are offered to make this compatible with other frontends. In theory, this makes
//! the frontend pluggable which could improve testing.
use std::collections::HashMap;
use std::marker::PhantomData;
use super::{decode_query, ClientParameter, CodeRef, IssuerRef, QueryMap};
use url::Url;

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
    urldecoded: ClientParameter<'static>,
}

fn extract_parameters(params: HashMap<String, Vec<String>>) -> Result<ClientParameter<'static>, String> {
    let query = params.iter()
        .filter(|&(_, v)| v.len() == 1)
        .map(|(k, v)| (k.clone().into(), v[0].clone().into()))
        .collect::<QueryMap<'static>>();
    decode_query(query)
}

impl AuthorizationFlow {
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

    pub fn handle<'l, Req, Auth>(mut granter: CodeRef, prepared: PreparedAuthorization<Req>, page_handler: &'l Auth) -> Result<<Req as WebRequest>::Response, OAuthError> where
        Req: WebRequest,
        Auth: OwnerAuthorizer<Request=Req> + 'l
    {
        let PreparedAuthorization { request: req, urldecoded } = prepared;
        let negotiated = match granter.negotiate(urldecoded.client_id, urldecoded.scope, urldecoded.redirect_url) {
            Err(st) => return Err(OAuthError::BadRequest(st)),
            Ok(v) => v,
        };

        let auth = AuthenticationRequest{ client_id: negotiated.client_id.to_string(), scope: negotiated.scope.to_string() };
        let owner = match page_handler.get_owner_authorization(req, auth)? {
            (Authentication::Failed, _)
                => return Err(OAuthError::AuthenticationFailed),
            (Authentication::InProgress, response)
                => return Ok(response),
            (Authentication::Authenticated(v), _) => v,
        };

        let redirect_to = granter.authorize(
            owner.clone().into(),
            negotiated,
            urldecoded.state.clone());

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
            Err(st) => return Err(OAuthError::BadRequest(st.into_owned())),
            Ok(token) => token,
        };

        Req::Response::text(&(token.token + " with refresh " + &token.refresh + " valid until " + &token.until.to_rfc2822()))
    }
}

pub enum OAuthError {
    MissingQuery,
    BadRequest(String),
    AuthenticationFailed,
    Other(String),
}
