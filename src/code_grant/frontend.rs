//! General algorithms for frontends.
//!
//! To ensure the adherence to the oauth2 rfc and the improve general implementations, the control
//! flow of incoming packets is specified here instead of the frontend implementations.
//! Instead, traits are offered to make this compatible with other frontends. In theory, this makes
//! the frontend pluggable which could improve testing.
use std::collections::HashMap;
use super::{decode_query, ClientParameter, CodeRef, QueryMap};
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
    fn query(&self) -> Option<HashMap<String, Vec<String>>>;
}

pub trait WebResponse where Self: Sized {
    fn redirect(url: Url) -> Result<Self, OAuthError>;
}

pub trait OwnerAuthorizer {
    type Request: WebRequest;
    fn get_owner_authorization(&self, &mut Self::Request, AuthenticationRequest) -> Result<(Authentication, <Self::Request as WebRequest>::Response), OAuthError>;
}

pub struct AuthorizationFlow;
pub struct AuthorizationRef<'l, Req> where
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
    pub fn prepare<W: WebRequest>(incoming: &mut W) -> Result<AuthorizationRef<W>, OAuthError> {
        let urlparameters = match incoming.query() {
            None => return Err(OAuthError::MissingQuery),
            Some(res) => res,
        };

        let urldecoded = match extract_parameters(urlparameters) {
            Err(st) => return Err(OAuthError::BadRequest(st)),
            Ok(url) => url,
        };

        Ok(AuthorizationRef{request: incoming, urldecoded})
    }

    pub fn handle<'l, Req, Auth>(mut granter: CodeRef, prepared: AuthorizationRef<Req>, page_handler: &'l Auth) -> Result<<Req as WebRequest>::Response, OAuthError> where
        Req: WebRequest,
        Auth: OwnerAuthorizer<Request=Req> + 'l
    {
        let AuthorizationRef { request: req, urldecoded } = prepared;
        let negotiated = match granter.negotiate(urldecoded.client_id, urldecoded.scope, urldecoded.redirect_url) {
            Err(st) => return Err(OAuthError::BadRequest(st)),
            Ok(v) => v
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

pub enum OAuthError {
    MissingQuery,
    BadRequest(String),
    AuthenticationFailed,
    Other(String),
}
