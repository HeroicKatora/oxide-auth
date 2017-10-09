use chrono::DateTime;
use chrono::Utc;

use iron::modifiers::Redirect;
use iron::IronResult;
use iron::Response;
use iron::Url;

use iron;
use std;

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
    fn authorize(&self, &Request) -> String;
    fn recover_parameters(&self, &str) -> AuthorizationParameters;
}

pub trait ClientInterface {
    fn negotiate(&self, scope: Option<&str>, redirect_url: Option<&str>) -> Result<(&str, &Url), &'static str>;
}

pub struct CodeGranter<'a> {
    authorizer: &'a Authorizer,
    client_interface: &'a ClientInterface
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
    -> Result<Request<'a>, &'static str> {
        match query.get("response_type").map(|s| s == "code") {
            None => return Err("Response type needs to be set"),
            Some(false) => return Err("Invalid response type"),
            Some(true) => ()
        }
        let client_id = match query.get("client_id") {
            None => return Err("client_id needs to be set"),
            Some(s) => s
        };
        let (scope, redir) = self.client_interface.negotiate(
            query.get("scope").map(|s| s.as_ref()),
            query.get("redirect_url").map(|s| s.as_ref()))?;
        Ok(Request{client_id: client_id, scope: scope, redirect_url: redir})
    }
}
