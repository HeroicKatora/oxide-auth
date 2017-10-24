extern crate iron;
extern crate urlencoded;

use super::code_grant::*;
use super::code_grant::frontend::{AuthorizationFlow, GrantFlow, OAuthError, OwnerAuthorizer, WebRequest, WebResponse};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, LockResult, MutexGuard};
use std::ops::DerefMut;
use self::iron::prelude::*;
use self::iron::modifiers::Redirect;
use self::urlencoded::{UrlEncodedBody, UrlEncodedQuery};
use url::Url as urlUrl;

/// Groups together all partial systems used in the code_grant process.
///
/// Since iron makes heavy use of asynchronous processing, we ensure sync and mutability on the
/// individual parts. In a later version this might change to only wrap for types where this is
/// needed.
pub struct IronGranter<R, A, I> where
    R: Registrar + Send + 'static,
    A: Authorizer + Send + 'static,
    I: Issuer + Send + 'static
{
    registrar: Arc<Mutex<R>>,
    authorizer: Arc<Mutex<A>>,
    issuer: Arc<Mutex<I>>,
}

/// Handles authorization requests from user-agents directed by clients.
///
/// Only holds handles to authorization relevant objects. An additional external handler is used
/// to communicate with the owner authorization process.
pub struct IronAuthorizer<R, A> where
    R: Registrar + Send + 'static,
    A: Authorizer + Send + 'static,
{
    page_handler: Box<OwnerAuthorizer<Request=iron::Request>>,
    registrar: Arc<Mutex<R>>,
    authorizer: Arc<Mutex<A>>,
}

/// Handles token requests from clients.
///
/// WIP: Client authorization is currently not supported, making this extremely insecure. Basic
/// auth with a registered secret should be used instead.
pub struct IronTokenRequest<A, I> where
    A: Authorizer + Send + 'static,
    I: Issuer + Send + 'static
{
    authorizer: Arc<Mutex<A>>,
    issuer: Arc<Mutex<I>>,
}

/// Sent to the OwnerAuthorizer to request owner permission.
pub struct AuthenticationRequest {
    pub client_id: String,
    pub scope: String,
}

impl iron::typemap::Key for AuthenticationRequest { type Value = AuthenticationRequest; }

/// Answer from OwnerAuthorizer to indicate the owners choice.
#[derive(Clone)]
pub enum Authentication {
    Failed,
    InProgress,
    Authenticated(String),
}

impl iron::typemap::Key for Authentication { type Value = Authentication; }

/// Use an iron request as an owner authorizer.
///
/// The extension system on requests and responses is used to insert and extract the query and
/// response which makes it possible to leverage irons' builtin wrapper system to build safer
/// and more intuitive implementations (e.g. by reusing existing authorization handlers to
/// enforce user login).
/// ```rust
/// // TODO: example needed for this seemingly more complex and common use case
/// ```
impl OwnerAuthorizer for iron::Handler {
    fn get_owner_authorization(&self, req: &mut iron::Request, auth: AuthenticationRequest)
    -> Result<(Authentication, Response), IronError> {
        req.extensions.insert::<AuthenticationRequest>(auth);
        let response = self.handle(req)?;
        match req.extensions.get::<Authentication>() {
            None => return Ok((Authentication::Failed, Response::with((iron::status::InternalServerError, "No authentication response")))),
            Some(v) => return Ok((v.clone(), response)),
        };
    }
}

impl<F> OwnerAuthorizer for F
where F: Fn(&mut iron::Request, AuthenticationRequest) -> Result<(Authentication, Response), IronError> + Send + Sync + 'static {
    fn get_owner_authorization(&self, req: &mut iron::Request, auth: AuthenticationRequest)
    -> Result<(Authentication, Response), IronError> {
        self(req, auth)
    }
}

impl OwnerAuthorizer for Box<iron::Handler> {
    fn get_owner_authorization(&self, req: &mut iron::Request, auth: AuthenticationRequest)
    -> Result<(Authentication, Response), IronError> {
        self.as_ref().get_owner_authorization(req, auth)
    }
}

impl<'a, 'b> WebRequest for iron::Request<'a, 'b> {
    type Response = iron::Response;
    fn query(&mut self) -> Option<HashMap<String, Vec<String>>> {
        self.get::<UrlEncodedQuery>().ok()
    }

    fn urlbody(&mut self) -> Option<&HashMap<String, Vec<String>>> {
        self.get_ref::<UrlEncodedBody>().ok()
    }
}

impl WebResponse for iron::Response {
    fn redirect(url: urlUrl) -> Result<Response, OAuthError> {
        let real_url = match iron::Url::from_generic_url(url) {
            Err(_) => return Err(OAuthError::Other("Error parsing redirect target".to_string())),
            Ok(v) => v,
        };
        Ok(Response::with((iron::status::Found, Redirect(real_url))))
    }

    fn text(text: &str) -> Result<Response, OAuthError> {
        Ok(Response::with((iron::status::Ok, text)))
    }
}

impl<R, A, I> IronGranter<R, A, I> where
    R: Registrar + Send + 'static,
    A: Authorizer + Send + 'static,
    I: Issuer + Send + 'static
{
    pub fn new(registrar: R, data: A, issuer: I) -> IronGranter<R, A, I> {
        IronGranter {
            registrar: Arc::new(Mutex::new(registrar)),
            authorizer: Arc::new(Mutex::new(data)),
            issuer: Arc::new(Mutex::new(issuer)) }
    }

    pub fn authorize<H: OwnerAuthorizer>(&self, page_handler: H) -> IronAuthorizer<R, A> {
        IronAuthorizer {
            authorizer: self.authorizer.clone(),
            page_handler: Box::new(page_handler),
            registrar: self.registrar.clone() }
    }

    pub fn token(&self) -> IronTokenRequest<A, I> {
        IronTokenRequest { authorizer: self.authorizer.clone(), issuer: self.issuer.clone() }
    }

    pub fn registrar(&self) -> LockResult<MutexGuard<R>> {
        self.registrar.lock()
    }

    pub fn authorizer(&self) -> LockResult<MutexGuard<A>> {
        self.authorizer.lock()
    }
    pub fn issuer(&self) -> LockResult<MutexGuard<I>> {
        self.issuer.lock()
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

fn from_oauth_error(error: OAuthError) -> IronResult<Response> {
    match error {
        _ => Ok(Response::with(iron::status::InternalServerError))
    }
}

impl<R, A> iron::Handler for IronAuthorizer<R, A> where
    R: Registrar + Send + 'static,
    A: Authorizer + Send + 'static
{
    fn handle<'a>(&'a self, req: &mut iron::Request) -> IronResult<Response> {
        let prepared = match AuthorizationFlow::prepare(req).map_err(from_oauth_error) {
            Err(res) => return res,
            Ok(v) => v,
        };

        let locked_registrar = self.registrar.lock().unwrap();
        let locked_authorizer = self.authorizer.lock().unwrap();
        let code = CodeRef { registrar: locked_registrar.deref_mut(), authorizer: locked_authorizer.deref_mut() };

        AuthorizationFlow::handle(code, prepared, &self.page_handler).or_else(from_oauth_error)
    }
}


impl<A, I> iron::Handler for IronTokenRequest<A, I> where
    A: Authorizer + Send + 'static,
    I: Issuer + Send + 'static
{
    fn handle<'a>(&'a self, req: &mut iron::Request) -> IronResult<Response> {
        let prepared = match GrantFlow::prepare(req).map_err(from_oauth_error) {
            Err(res) => return res,
            Ok(v) => v,
        };

        let locked_authorizer = self.authorizer.lock().unwrap();
        let locked_issuer = self.issuer.lock().unwrap();
        let issuer = IssuerRef { authorizer: locked_authorizer.deref_mut(), issuer: locked_issuer.deref_mut() };

        GrantFlow::handle(issuer, prepared).or_else(from_oauth_error)
    }
}

/// Reexport most useful structs as well as the code_grant core library.
pub mod prelude {
    pub use code_grant::prelude::*;
    pub use super::{IronGranter, AuthenticationRequest, Authentication};
}
