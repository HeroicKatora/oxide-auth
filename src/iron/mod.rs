extern crate iron;
extern crate urlencoded;

use super::code_grant::*;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, LockResult, MutexGuard};
use std::ops::DerefMut;
use self::iron::prelude::*;
use self::iron::modifiers::Redirect;
use self::iron::{AroundMiddleware, Handler};
use self::urlencoded::{UrlEncodedBody, UrlEncodedQuery, QueryMap as UQueryMap};

pub struct IronGranter<A, I> where
    A: Authorizer + Send + 'static,
    I: Issuer + Send + 'static
{
    authorizer: Arc<Mutex<A>>,
    issuer: Arc<Mutex<I>>,
}

pub struct IronAuthorizer<A: Authorizer + Send + 'static> {
    page_handler: Box<Handler>,
    authorizer: Arc<Mutex<A>>,
}

pub struct IronTokenRequest<A, I> where
    A: Authorizer + Send + 'static,
    I: Issuer + Send + 'static
{
    authorizer: Arc<Mutex<A>>,
    issuer: Arc<Mutex<I>>,
}

pub struct AuthenticationRequest {
    pub client_id: String,
    pub scope: String,
}

impl iron::typemap::Key for AuthenticationRequest { type Value = AuthenticationRequest; }

pub enum Authentication {
    Failed,
    InProgress,
    Authenticated(String),
}

impl iron::typemap::Key for Authentication { type Value = Authentication; }

pub trait OwnerAuthorizer: Send + Sync + 'static {
    fn get_owner_authorization(&self, &mut iron::Request, AuthenticationRequest) -> Result<(Authentication, Response), String>;
}

impl Into<Box<Handler>> for Box<OwnerAuthorizer> {
    fn into(self: Self) -> Box<Handler> {
        Box::new(move |req: &mut iron::Request| {
            let (client, scope) = match req.extensions.get::<AuthenticationRequest>() {
                None => return Ok(Response::with((iron::status::InternalServerError, "Expected to be invoked as oauth authentication"))),
                Some(req) => (req.client_id.clone(), req.scope.clone()),
            };

            let (auth, resp) = match self.get_owner_authorization(req, AuthenticationRequest{client_id: client, scope: scope}) {
                Err(text) => return Ok(Response::with((iron::status::InternalServerError, text))),
                Ok(auth) => auth,
            };

            req.extensions.insert::<Authentication>(auth);
            Ok(resp)
        })
    }
}

impl<A, I> IronGranter<A, I> where
    A: Authorizer + Send + 'static,
    I: Issuer + Send + 'static
{
    pub fn new(data: A, issuer: I) -> IronGranter<A, I> {
        IronGranter { authorizer: Arc::new(Mutex::new(data)), issuer: Arc::new(Mutex::new(issuer)) }
    }

    pub fn authorize(&self, page_handler: Box<Handler>) -> IronAuthorizer<A> {
        IronAuthorizer { authorizer: self.authorizer.clone(), page_handler: page_handler }
    }

    pub fn token(&self) -> IronTokenRequest<A, I> {
        IronTokenRequest { authorizer: self.authorizer.clone(), issuer: self.issuer.clone() }
    }

    pub fn authorizer(&self) -> LockResult<MutexGuard<A>> {
        self.authorizer.lock()
    }
}

#[derive(Debug)]
pub struct ExpectAuthenticationHandler;

impl fmt::Display for ExpectAuthenticationHandler {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Expected an authentication handler to handle this response")
    }
}

impl Error for ExpectAuthenticationHandler {
    fn description(&self) -> &str {
        "Expected an authentication handler to handle this response"
    }
}

impl self::iron::modifier::Modifier<Response> for ExpectAuthenticationHandler {
    fn modify(self, response: &mut Response) {
        response.status = Some(iron::status::InternalServerError);
        response.body = Some(Box::new("Unhandled authentication response"));
    }
}

fn try_convert_urlparamters(params: UQueryMap) -> Result<ClientParameter<'static>, String> {
    let query = params.iter().filter_map(|(k, v)| {
            if v.len() == 1 {
                Some((k.clone().into(), v[0].clone().into()))
            } else {
                None
            }
        }).collect::<QueryMap<'static>>();
    decode_query(query)
}

impl<A: Authorizer + Send + 'static> iron::Handler for IronAuthorizer<A> {
    fn handle<'a>(&'a self, req: &mut iron::Request) -> IronResult<Response> {
        let urlparameters = match req.get::<UrlEncodedQuery>() {
            Ok(res) => res,
            _ => return Ok(Response::with((iron::status::BadRequest, "Missing valid url encoded parameters"))),
        };

        let urldecoded = match try_convert_urlparamters(urlparameters) {
            Ok(url) => url,
            Err(st) => return Ok(Response::with((iron::status::BadRequest, st))),
        };

        let mut locked = self.authorizer.lock().unwrap();
        let mut granter = CodeRef::with(locked.deref_mut());

        let negotiated = match granter.negotiate(urldecoded.client_id, urldecoded.scope, urldecoded.redirect_url) {
            Err(st) => return Ok(Response::with((iron::status::BadRequest, st))),
            Ok(v) => v
        };

        req.extensions.insert::<AuthenticationRequest>(
            AuthenticationRequest{
                client_id: negotiated.client_id.to_string(),
                scope: negotiated.scope.to_string()});

        let inner_result = self.page_handler.handle(req);

        let owner = match req.extensions.get::<Authentication>() {
            None => return Ok(Response::with((iron::status::InternalServerError, "Authenication failed"))),
            Some(reference) => match reference {
                &Authentication::Failed => return Ok(Response::with((iron::status::BadRequest, "Authenication failed"))),
                &Authentication::InProgress => return inner_result,
                &Authentication::Authenticated(ref v) => v
            }
        };

        let redirect_to = granter.authorize(
            owner.clone().into(),
            negotiated,
            urldecoded.state.clone());

        let real_url = match iron::Url::from_generic_url(redirect_to) {
            Ok(v) => v,
            _ => return Ok(Response::with((iron::status::InternalServerError, "Error parsing redirect target"))),
        };
        Ok(Response::with((iron::status::Found, Redirect(real_url))))
    }
}


impl<A, I> iron::Handler for IronTokenRequest<A, I> where
    A: Authorizer + Send + 'static,
    I: Issuer + Send + 'static
{
    fn handle<'a>(&'a self, req: &mut iron::Request) -> IronResult<Response> {
        let query = match req.get_ref::<UrlEncodedBody>() {
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
        let mut issuelocked = self.issuer.lock().unwrap();
        let mut issuer = IssuerRef::with(authlocked.deref_mut(), issuelocked.deref_mut());

        let token = match issuer.use_code(code, client.into(), redirect_url.into()) {
            Err(st) => return Ok(Response::with((iron::status::BadRequest, st.as_ref()))),
            Ok(token) => token
        };

        Ok(Response::with((iron::status::Ok, token.as_ref())))
    }
}
