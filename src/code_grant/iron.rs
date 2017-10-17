use super::*;
extern crate iron;
extern crate urlencoded;
use std::ops::DerefMut;
use self::iron::prelude::*;
use self::iron::modifiers::Redirect;
use self::iron::Request as IRequest;
use self::urlencoded::UrlEncodedQuery;

pub struct IronGranter<A: Authorizer + Send + 'static> {
    authorizer: std::sync::Arc<std::sync::Mutex<A>>
}

pub struct IronAuthorizer<A: Authorizer + Send + 'static> {
    authorizer: std::sync::Arc<std::sync::Mutex<A>>
}

pub struct IronTokenRequest<A: Authorizer + Send + 'static> {
    authorizer: std::sync::Arc<std::sync::Mutex<A>>
}

impl<A: Authorizer + Send + 'static> IronGranter<A> {
    pub fn new(data: A) -> IronGranter<A> {
        IronGranter { authorizer: std::sync::Arc::new(std::sync::Mutex::new(data)) }
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
        let mut granter = GrantRef::with(locked.deref_mut());

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
                => (&clientv[0], &codev[0], &redirect_urlv[0]),
            _ => return Ok(Response::with((iron::status::BadRequest, "Invalid parameters")))
        };

        let mut locked = self.authorizer.lock().unwrap();
        let mut granter = GrantRef::with(locked.deref_mut());

        let saved_params = match granter.authorizer.recover_parameters(code) {
            Some(v) => v,
            _ => return Ok(Response::with((iron::status::BadRequest, "Inactive code")))
        };

        if saved_params.client_id != client || redirect_url != saved_params.redirect_url.as_str() {
            return Ok(Response::with((iron::status::BadRequest, "Invalid code")))
        }

        Ok(Response::with((iron::status::Ok, )))
    }
}
