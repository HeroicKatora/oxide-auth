extern crate iron;
extern crate urlencoded;

use super::code_grant::*;
use super::code_grant::frontend::{AuthorizationFlow, GrantFlow, OAuthError, OwnerAuthorizer, WebRequest, WebResponse};
pub use super::code_grant::frontend::{AuthenticationRequest, Authentication};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, LockResult, MutexGuard};
use std::ops::DerefMut;
use std::marker::PhantomData;
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
pub struct IronAuthorizer<PH, R, A> where
    PH: GenericOwnerAuthorizer + Send + Sync,
    R: Registrar + Send + 'static,
    A: Authorizer + Send + 'static,
{
    page_handler: Box<PH>,
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

impl iron::typemap::Key for AuthenticationRequest { type Value = AuthenticationRequest; }

impl iron::typemap::Key for Authentication { type Value = Authentication; }

pub trait GenericOwnerAuthorizer {
    fn get_owner_authorization(&self, &mut iron::Request, AuthenticationRequest) -> Result<(Authentication, iron::Response), OAuthError>;
}

/// Use an iron request as an owner authorizer.
///
/// The extension system on requests and responses is used to insert and extract the query and
/// response which makes it possible to leverage irons' builtin wrapper system to build safer
/// and more intuitive implementations (e.g. by reusing existing authorization handlers to
/// enforce user login).
/// ```rust
/// // TODO: example needed for this seemingly more complex and common use case
/// ```
impl GenericOwnerAuthorizer for iron::Handler {
    fn get_owner_authorization(&self, req: &mut iron::Request, auth: AuthenticationRequest)
    -> Result<(Authentication, Response), OAuthError> {
        req.extensions.insert::<AuthenticationRequest>(auth);
        let response = self.handle(req).map_err(|_| OAuthError::Other("Internal error".to_string()))?;
        match req.extensions.get::<Authentication>() {
            None => return Ok((Authentication::Failed, Response::with((iron::status::InternalServerError, "No authentication response")))),
            Some(v) => return Ok((v.clone(), response)),
        };
    }
}

impl<F> GenericOwnerAuthorizer for F
where F: Fn(&mut iron::Request, AuthenticationRequest) -> Result<(Authentication, Response), OAuthError> + Send + Sync + 'static {
    fn get_owner_authorization(&self, req: &mut iron::Request, auth: AuthenticationRequest)
    -> Result<(Authentication, Response), OAuthError> {
        self(req, auth)
    }
}

impl GenericOwnerAuthorizer for Box<iron::Handler> {
    fn get_owner_authorization(&self, req: &mut iron::Request, auth: AuthenticationRequest)
    -> Result<(Authentication, Response), OAuthError> {
        self.as_ref().get_owner_authorization(req, auth)
    }
}

struct SpecificOwnerAuthorizer<'l, 'a, 'b: 'a>(&'l GenericOwnerAuthorizer, PhantomData<iron::Request<'a, 'b>>);

impl<'l, 'a, 'b: 'a> OwnerAuthorizer for SpecificOwnerAuthorizer<'l, 'a, 'b> {
    type Request = iron::Request<'a, 'b>;
    fn get_owner_authorization(&self, req: &mut Self::Request, auth: AuthenticationRequest)
    -> Result<(Authentication, Response), OAuthError> {
        self.0.get_owner_authorization(req, auth)
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

    pub fn authorize<H: GenericOwnerAuthorizer + Send + Sync>(&self, page_handler: H) -> IronAuthorizer<H, R, A> {
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

impl<PH, R, A> iron::Handler for IronAuthorizer<PH, R, A> where
    PH: GenericOwnerAuthorizer + Send + Sync + 'static,
    R: Registrar + Send + 'static,
    A: Authorizer + Send + 'static
{
    fn handle<'a>(&'a self, req: &mut iron::Request) -> IronResult<Response> {
        let prepared = match AuthorizationFlow::prepare(req).map_err(from_oauth_error) {
            Err(res) => return res,
            Ok(v) => v,
        };

        let mut locked_registrar = self.registrar.lock().unwrap();
        let mut locked_authorizer = self.authorizer.lock().unwrap();
        let code = CodeRef::with(locked_registrar.deref_mut(), locked_authorizer.deref_mut());

        let handler = SpecificOwnerAuthorizer(self.page_handler.as_ref(), PhantomData);
        AuthorizationFlow::handle(code, prepared, &handler).or_else(from_oauth_error)
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

        let mut locked_authorizer = self.authorizer.lock().unwrap();
        let mut locked_issuer = self.issuer.lock().unwrap();
        let issuer = IssuerRef::with(locked_authorizer.deref_mut(), locked_issuer.deref_mut());

        GrantFlow::handle(issuer, prepared).or_else(from_oauth_error)
    }
}

/// Reexport most useful structs as well as the code_grant core library.
pub mod prelude {
    pub use code_grant::prelude::*;
    pub use super::{IronGranter, AuthenticationRequest, Authentication};
}
