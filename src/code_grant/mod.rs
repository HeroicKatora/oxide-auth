use chrono::DateTime;
use chrono::Utc;

use iron::modifiers::Redirect;
use iron::IronResult;
use iron::Response;
use iron::Url;

use iron;
use std;

pub struct NegotiationParams<'a> {
    pub client_id: &'a str,
    pub scope: Option<&'a str>,
    pub redirect_url: Option<&'a str>
}

pub struct Request<'a> {
    pub client_id: &'a str,
    pub redirect_url: &'a Url,
    pub scope: &'a str,
}

impl<'a> Request<'a> {
    pub fn response_type(&self) -> &'static str {
        return "code"
    }
}

pub struct AuthorizationParameters<'a> {
    pub client_id: &'a str,
    pub redirect_url: &'a Url,
    pub scope: &'a str,
    pub until: &'a DateTime<Utc>
}

pub trait Authorizer {
    fn negotiate<'a>(&self, NegotiationParams<'a>) -> Result<Request<'a>, &str>;
    fn authorize(&self, &Request) -> String;
    fn recover_parameters(&self, &str) -> AuthorizationParameters;
}

pub struct CodeGranter<'a> {
    authorizer: &'a Authorizer,
}

type QueryMap<'a> = std::collections::HashMap<std::borrow::Cow<'a, str>, std::borrow::Cow<'a, str>>;

impl<'a> CodeGranter<'a> {
    pub fn iron_auth_handler(&self, req: &mut iron::Request) -> IronResult<Response> {
        let urldecoded = self.decode_query(&req.url);
        let auth = match self.auth_url_encoded(&urldecoded) {
            Err(st) => return Ok(Response::with((super::iron::status::BadRequest, st))),
            Ok(v) => v
        };
        let grant = self.authorizer.authorize(&auth);
        let redirect_to = {
            let mut url = auth.redirect_url.clone();
            url.as_mut().query_pairs_mut()
                .append_pair("code", grant.as_str())
                .extend_pairs(urldecoded.get("state").map(|v| ("state", v)))
                .finish();
            url
        };

        Ok(Response::with((super::iron::status::Ok, Redirect(redirect_to))))
    }

    fn decode_query(&self, query: &'a Url) -> QueryMap<'a> {
        query.as_ref().query_pairs()
            .collect::<QueryMap<'a>>()
    }

    fn auth_url_encoded(&self, query: &'a QueryMap<'a>)
    -> Result<Request<'a>, &'a str> {
        match query.get("response_type").map(|s| s == "code") {
            None => return Err("Response type needs to be set"),
            Some(false) => return Err("Invalid response type"),
            Some(true) => ()
        }
        let client_id = match query.get("client_id") {
            None => return Err("client_id needs to be set"),
            Some(s) => s
        };
        let (scope, redir) = self.authorizer.negotiate(NegotiationParams {
            client_id: client_id,
            scope: query.get("scope").map(|s| s.as_ref()),
            redirect_url: query.get("redirect_url").map(|s| s.as_ref())}
        ).map(|p| (p.scope, p.redirect_url))?;
        Ok(Request{client_id: client_id, scope: scope, redirect_url: redir})
    }
}

pub mod authorizer;
