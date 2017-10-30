use chrono::DateTime;
use chrono::Utc;
use url::Url;

use std::borrow::Cow;
use std::collections::HashMap;

type Time = DateTime<Utc>;

pub struct ClientParameter<'a> {
    pub client_id: Cow<'a, str>,
    pub scope: Option<Cow<'a, str>>,
    pub redirect_url: Option<Cow<'a, Url>>,
    pub state: Option<Cow<'a, str>>,
}

pub struct NegotiationParameter<'a> {
    pub client_id: Cow<'a, str>,
    pub scope: Option<Cow<'a, str>>,
    pub redirect_url: Option<Cow<'a, Url>>,
}

pub struct Negotiated<'a> {
    pub client_id: Cow<'a, str>,
    pub scope: Cow<'a, str>,
    pub redirect_url: Url,
}

pub struct Request<'a> {
    pub owner_id: &'a str,
    pub client_id: &'a str,
    pub redirect_url: &'a Url,
    pub scope: &'a str,
}

pub struct Grant<'a> {
    pub owner_id: Cow<'a, str>,
    pub client_id: Cow<'a, str>,
    pub redirect_url: Cow<'a, Url>,
    pub scope: Cow<'a, str>,
    pub until: Cow<'a, Time>,
}

#[derive(Clone, Debug)]
pub struct IssuedToken {
    pub token: String,
    pub refresh: String,
    pub until: Time,
}

/// Registrars provie a way to interact with clients.
///
/// Most importantly, they determine defaulted parameters for a request as well as the validity
/// of provided parameters. In general, implementations of this trait will probably offer an
/// interface for registering new clients. This interface is not covered by this library.
pub trait Registrar {
    fn negotiate<'a>(&self, NegotiationParameter<'a>) -> Result<Negotiated<'a>, String>;
}

/// Authorizers create and manage authorization codes.
///
/// The authorization code can be traded for a bearer token at the token endpoint.
pub trait Authorizer {
    fn authorize(&mut self, Request) -> String;
    fn recover_parameters<'a>(&'a self, &'a str) -> Option<Grant<'a>>;
}

/// Issuers create bearer tokens..
///
/// It's the issuers decision whether a refresh token is offered or not. In any case, it is also
/// responsible for determining the validity and parameters of any possible token string.
pub trait Issuer {
    fn issue(&mut self, Request) -> IssuedToken;
    fn recover_token<'a>(&'a self, &'a str) -> Option<Grant<'a>>;
    fn recover_refresh<'a>(&'a self, &'a str) -> Option<Grant<'a>>;
}

/// Generic token for a specific grant.
///
/// The interface may be reused for authentication codes, bearer tokens and refresh tokens.
pub trait TokenGenerator {
    fn generate(&self, &Grant) -> String;
}

pub type QueryMap<'a> = HashMap<Cow<'a, str>, Cow<'a, str>>;

pub fn decode_query<'u>(kvpairs: QueryMap<'u>) -> Result<ClientParameter<'u>, String> {

    match kvpairs.get("response_type").map(|s| *s == "code") {
        None => return Err("Response type needs to be set".to_string()),
        Some(false) => return Err("Invalid response type".to_string()),
        Some(true) => ()
    }
    let client_id = match kvpairs.get("client_id") {
        None => return Err("client_id needs to be set".to_string()),
        Some(s) => s.clone()
    };
    let redirect_url = match kvpairs.get("redirect_url").map(|st| Url::parse(st)) {
        Some(Err(_)) => return Err("Invalid url".to_string()),
        val => val.map(|v| Cow::Owned(v.unwrap()))
    };
    let state = kvpairs.get("state").map(|v| v.clone());
    Ok(ClientParameter {
        client_id: client_id,
        scope: kvpairs.get("scope").map(|v| v.clone()),
        redirect_url: redirect_url,
        state: state
    })
}

pub struct CodeRef<'a> {
    registrar: &'a Registrar,
    authorizer: &'a mut Authorizer,
}

impl<'u> CodeRef<'u> {
    pub fn negotiate<'a>(&self, client_id: Cow<'a, str>, scope: Option<Cow<'a, str>>, redirect_url: Option<Cow<'a, Url>>)
    -> Result<Negotiated<'a>, String> {
        self.registrar.negotiate(NegotiationParameter{client_id, scope, redirect_url})
    }

    pub fn authorize<'a>(&'a mut self, owner_id: Cow<'a, str>, negotiated: Negotiated<'a>, state: Option<Cow<'a, str>>) -> Url {
        let grant = self.authorizer.authorize(Request{
            owner_id: &owner_id,
            client_id: &negotiated.client_id,
            redirect_url: &negotiated.redirect_url,
            scope: &negotiated.scope});
        let mut url = negotiated.redirect_url;
        url.query_pairs_mut()
            .append_pair("code", grant.as_str())
            .extend_pairs(state.map(|v| ("state", v)))
            .finish();
        url
    }

    pub fn with<'a>(registrar: &'a Registrar, t: &'a mut Authorizer) -> CodeRef<'a> {
        CodeRef { registrar, authorizer: t }
    }
}

pub struct IssuerRef<'a> {
    authorizer: &'a mut Authorizer,
    issuer: &'a mut Issuer,
}

impl<'u> IssuerRef<'u> {
    pub fn use_code<'a>(&'a mut self, code: String, expected_client: Cow<'a, str>, expected_url: Cow<'a, str>)
    -> Result<IssuedToken, Cow<'static, str>> {
        let saved_params = match self.authorizer.recover_parameters(code.as_ref()) {
            None => return Err("Inactive code".into()),
            Some(v) => v,
        };

        if saved_params.client_id != expected_client || expected_url != saved_params.redirect_url.as_str() {
            return Err("Invalid code".into())
        }

        if saved_params.until.as_ref() < &Utc::now() {
            return Err("Code no longer valid".into())
        }

        let token = self.issuer.issue(Request{
            client_id: &saved_params.client_id,
            owner_id: &saved_params.owner_id,
            redirect_url: &saved_params.redirect_url,
            scope: &saved_params.scope,
        });
        Ok(token)
    }

    pub fn with<'a>(t: &'a mut Authorizer, i: &'a mut Issuer) -> IssuerRef<'a> {
        IssuerRef { authorizer: t, issuer: i }
    }
}

pub mod authorizer;
pub mod error;
pub mod frontend;
pub mod generator;
pub mod issuer;
pub mod registrar;

pub mod prelude {
    pub use super::authorizer::Storage;
    pub use super::issuer::{TokenMap, TokenSigner};
    pub use super::generator::RandomGenerator;
    pub use super::QueryMap;
    pub use super::registrar::ClientMap;
}
