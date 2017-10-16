use chrono::DateTime;
use chrono::Utc;
use iron::Url;

use std;
use std::borrow::Cow;

pub struct NegotiationParams<'a> {
    pub client_id: Cow<'a, str>,
    pub scope: Option<Cow<'a, str>>,
    pub redirect_url: Option<Cow<'a, Url>>,
    pub state: Option<Cow<'a, str>>,
}

pub struct Negotiated<'a> {
    pub client_id: Cow<'a, str>,
    pub scope: Cow<'a, str>,
    pub redirect_url: Url,
    pub state: Option<Cow<'a, str>>,
}

pub struct Request<'a> {
    pub owner_id: &'a str,
    pub client_id: &'a str,
    pub redirect_url: &'a Url,
    pub scope: &'a str,
}

pub struct Grant<'a> {
    pub owner_id: &'a str,
    pub client_id: &'a str,
    pub redirect_url: &'a Url,
    pub scope: &'a str,
    pub until: &'a DateTime<Utc>
}

pub trait Authorizer {
    fn negotiate<'a>(&self, NegotiationParams<'a>) -> Result<Negotiated<'a>, String>;
    fn authorize(&mut self, Request) -> String;
    fn recover_parameters<'a>(&'a self, &'a str) -> Option<Grant<'a>>;
}

pub trait WebRequest {
    fn owner_id(&self) -> Option<String>;
}

type QueryMap<'a> = std::collections::HashMap<std::borrow::Cow<'a, str>, std::borrow::Cow<'a, str>>;

fn decode_query<'u>(query: &'u Url) -> Result<NegotiationParams<'u>, String> {
    let kvpairs = query.as_ref().query_pairs()
        .collect::<QueryMap<'u>>();

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
    Ok(NegotiationParams {
        client_id: client_id,
        scope: kvpairs.get("scope").map(|v| v.clone()),
        redirect_url: redirect_url,
        state: state
    })
}

pub trait CodeGranter {
    fn authorizer_mut(&mut self) -> &mut Authorizer;
    fn authorizer(&self) -> &Authorizer;

    fn negotiate<'a>(&self, params: NegotiationParams<'a>)
    -> Result<Negotiated<'a>, String> {
        self.authorizer().negotiate(params)
    }

    fn authorize<'a>(&'a mut self, owner_id: Cow<'a, str>, negotiated: Negotiated<'a>) -> Url {
        let grant = self.authorizer_mut().authorize(Request{
            owner_id: &owner_id,
            client_id: &negotiated.client_id,
            redirect_url: &negotiated.redirect_url,
            scope: &negotiated.scope});
        let mut url = negotiated.redirect_url;
        url.as_mut().query_pairs_mut()
            .append_pair("code", grant.as_str())
            .extend_pairs(negotiated.state.map(|v| ("state", v)))
            .finish();
        url
    }
}

pub mod iron;
pub mod authorizer;
