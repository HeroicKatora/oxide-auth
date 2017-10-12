use super::*;
use iron;
use iron::modifiers::Redirect;
use iron::IronResult;
use iron::Response;
use iron::Request as IRequest;

pub struct IronGranter<A: Authorizer + Send + 'static> {
    authorizer: std::sync::Mutex<std::cell::RefCell<A>>
}

impl<A: Authorizer + Send + 'static> IronGranter<A> {
    pub fn new(data: A) -> IronGranter<A> {
        IronGranter { authorizer: std::sync::Mutex::new(std::cell::RefCell::new(data)) }
    }
}

impl<'a, 'b> WebRequest for IRequest<'a, 'b> {
    fn owner_id(&self) -> Option<String> {
        return Some("test".to_string());
    }
}

struct IronGrantRef<'a>(&'a mut Authorizer);

impl<'a> CodeGranter for IronGrantRef<'a> {
    fn authorizer_mut(&mut self) -> &mut Authorizer {
        self.0
    }

    fn authorizer(&self) -> &Authorizer {
        self.0
    }
}

impl<A: Authorizer + Send + 'static> iron::Handler for IronGranter<A> {
    fn handle<'a>(&'a self, req: &mut iron::Request) -> IronResult<Response> {
        use std::ops::Deref;
        use std::ops::DerefMut;
        let urldecoded = decode_query(&req.url);
        let locked = self.authorizer.lock().unwrap();
        let mut auth_ref = locked.deref().borrow_mut();
        let mut granter = IronGrantRef{0: auth_ref.deref_mut()};
        let (client_id, negotiated) = match granter.auth_url_encoded(&urldecoded) {
            Err(st) => return Ok(Response::with((iron::status::BadRequest, st))),
            Ok(v) => v
        };
        let redirect_to = granter.authorize(
            client_id,
            req.owner_id().unwrap(),
            negotiated,
            urldecoded.get("state").map(AsRef::as_ref));
        Ok(Response::with((iron::status::Found, Redirect(redirect_to))))
    }
}
