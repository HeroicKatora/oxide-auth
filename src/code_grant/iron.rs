use super::*;
extern crate iron;
use self::iron::modifiers::Redirect;
use self::iron::IronResult;
use self::iron::Response;
use self::iron::Request as IRequest;

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
        use std::ops::DerefMut;
        let urldecoded = match decode_query(req.url.as_ref()) {
            Err(st) => return Ok(Response::with((iron::status::BadRequest, st))),
            Ok(res) => res
        };

        let mut locked = self.authorizer.lock().unwrap();
        let mut auth_ref = locked.deref_mut();
        let mut granter = IronGrantRef{0: auth_ref.deref_mut()};

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
            Err(_) => return Ok(Response::with((iron::status::InternalServerError, "Error parsing redirect target"))),
            Ok(v) => v
        };
        Ok(Response::with((iron::status::Found, Redirect(real_url))))
    }
}


impl<A: Authorizer + Send + 'static> iron::Handler for IronTokenRequest<A> {
    fn handle<'a>(&'a self, req: &mut iron::Request) -> IronResult<Response> {
        let from_addr = format!("{}", req.remote_addr);
        Ok(Response::with((iron::status::Ok, from_addr)))
    }
}
