extern crate iron;
extern crate urlencoded;

use super::code_grant::*;
use std::sync::{Arc, Mutex};
use std::ops::DerefMut;
use self::iron::prelude::*;
use self::iron::modifiers::Redirect;
use self::iron::Request as IRequest;
use self::urlencoded::UrlEncodedQuery;

pub struct IronGranter<A: Authorizer + Send + 'static> {
    authorizer: Arc<Mutex<A>>
}

pub struct IronAuthorizer<A: Authorizer + Send + 'static> {
    authorizer: Arc<Mutex<A>>
}

pub struct IronTokenRequest<A: Authorizer + Send + 'static> {
    authorizer: Arc<Mutex<A>>
}

impl<A: Authorizer + Send + 'static> IronGranter<A> {
    pub fn new(data: A) -> IronGranter<A> {
        IronGranter { authorizer: Arc::new(Mutex::new(data)) }
    }

    pub fn authorize(&self) -> IronAuthorizer<A> {
        IronAuthorizer { authorizer: self.authorizer.clone() }
    }

    pub fn token(&self) -> IronTokenRequest<A> {
        IronTokenRequest { authorizer: self.authorizer.clone() }
    }
}

impl<'a, 'b> WebRequest for IRequest<'a, 'b> {
    fn authenticated_owner(&self) -> Option<String> {
        return Some("test".to_string());
    }
}

impl<A: Authorizer + Send + 'static> iron::Handler for IronAuthorizer<A> {
    fn handle<'a>(&'a self, req: &mut iron::Request) -> IronResult<Response> {
        let urldecoded = match decode_query(req.url.as_ref()) {
            Err(st) => return Ok(Response::with((iron::status::BadRequest, st))),
            Ok(res) => res
        };

        let mut locked = self.authorizer.lock().unwrap();
        let mut granter = CodeRef::with(locked.deref_mut());

        let negotiated = match granter.negotiate(urldecoded.client_id, urldecoded.scope, urldecoded.redirect_url) {
            Err(st) => return Ok(Response::with((iron::status::BadRequest, st))),
            Ok(v) => v
        };

        let owner = match req.authenticated_owner() {
            None => return Ok(Response::with((iron::status::Ok, "Please authenticate"))),
            Some(v) => v
        };

        let redirect_to = granter.authorize(
            owner.into(),
            negotiated,
            urldecoded.state.clone());

        let real_url = match iron::Url::from_generic_url(redirect_to) {
            Ok(v) => v,
            _ => return Ok(Response::with((iron::status::InternalServerError, "Error parsing redirect target"))),
        };
        Ok(Response::with((iron::status::Found, Redirect(real_url))))
    }
}


impl<A: Authorizer + Send + 'static> iron::Handler for IronTokenRequest<A> {
    fn handle<'a>(&'a self, req: &mut iron::Request) -> IronResult<Response> {
        let query = match req.get_ref::<UrlEncodedQuery>() {
            Ok(v) => v,
            _ => return Ok(Response::with((iron::status::BadRequest, "Body not url encoded"))),
        };
        let (grant_typev, clientv, codev, redirect_urlv) = match (
            query.get("grant_type"),
            query.get("client_id"),
            query.get("code"),
            query.get("redirect_url")) {
            (Some(grant), Some(client), Some(code), Some(redirect))
                => (grant, client, code, redirect),
            _ => return Ok(Response::with((iron::status::BadRequest, "Missing parameter")))
        };
        let lengths = (
            grant_typev.len(),
            clientv.len(),
            codev.len(),
            redirect_urlv.len());
        let (client, code, redirect_url) = match lengths {
            (1, 1, 1, 1) if grant_typev[0] == "authorization_code"
                => (clientv[0].as_str(), codev[0].to_string(), redirect_urlv[0].as_str()),
            _ => return Ok(Response::with((iron::status::BadRequest, "Invalid parameters")))
        };

        let mut authlocked = self.authorizer.lock().unwrap();
        let mut issuer = IssuerRef::with(authlocked.deref_mut());

        let token = match issuer.use_code(code, client.into(), redirect_url.into()) {
            Err(st) => return Ok(Response::with((iron::status::BadRequest, st.as_ref()))),
            Ok(token) => token
        };

        Ok(Response::with((iron::status::Ok, token.as_ref())))
    }
}
