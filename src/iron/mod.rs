//! Offers bindings for the code_grant module with iron servers.
//!
//! ## Hello world
//!
//! ```no_run
//! extern crate iron;
//! extern crate oxide_auth;
//! extern crate router;
//! use oxide_auth::iron::prelude::*;
//! use iron::prelude::*;
//! use std::thread;
//!
//! /// Example of a main function of a iron server supporting oauth.
//! fn main() {
//!     let passphrase = "This is a super secret phrase";
//!
//!     // Create the main token instance, a code_granter with an iron frontend.
//!     let ohandler = IronGranter::new(
//!         // Stores clients in a simple in-memory hash map.
//!         ClientMap::new(),
//!         // Authorization tokens are 16 byte random keys to a memory hash map.
//!         Storage::new(RandomGenerator::new(16)),
//!         // Bearer tokens are signed (but not encrypted) using a passphrase.
//!         TokenSigner::new_from_passphrase(passphrase));
//!
//!     // Register a dummy client instance
//!     ohandler.registrar().unwrap().register_client(
//!         "example",
//!         Url::parse("http://example.com/endpoint").unwrap());
//!
//!     // Create a router and bind the relevant pages
//!     let mut router = router::Router::new();
//!     router.get("/authorize", ohandler.authorize(handle_get), "authorize");
//!     router.post("/authorize", ohandler.authorize(IronOwnerAuthorizer(handle_post)),
//!         "authorize");
//!     router.post("/token", ohandler.token(), "token");
//!
//!     // Start the server
//!     let server = thread::spawn(||
//!         iron::Iron::new(router).http("localhost:8020").unwrap());
//!
//!     server.join().expect("Failed to run");
//! }
//!
//! /// A simple implementation of the first part of an authentication handler. This should
//! /// display a page to the user asking for his permission to proceed.
//! fn handle_get(_: &mut Request, auth: AuthenticationRequest) -> Result<(Authentication, Response), OAuthError> {
//!     unimplemented!()
//! }
//!
//! /// This shows the second style of authentication handler, a iron::Handler compatible form.
//! /// Allows composition with other libraries or frameworks built around iron.
//! fn handle_post(req: &mut Request) -> IronResult<Response> {
//!     unimplemented!()
//! }
//!
//! ```

extern crate iron;
extern crate urlencoded;

use super::code_grant::prelude::*;
use super::code_grant::{Authorizer, Issuer, Registrar};
use super::code_grant::frontend::{AuthorizationFlow, GrantFlow, OwnerAuthorizer, WebRequest, WebResponse};
pub use super::code_grant::frontend::{AuthenticationRequest, Authentication, OAuthError};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, LockResult, MutexGuard};
use std::ops::DerefMut;
use std::marker::PhantomData;
use self::iron::prelude::*;
use self::iron::modifiers::Redirect;
use self::urlencoded::{UrlEncodedBody, UrlEncodedQuery};
use url::Url;

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

/// Wraps an iron::Handler for use as an OwnerAuthorizer.
///
/// This allows interoperability with other iron libraries. On top of that, one can use the standard
/// middleware facilities to quickly stick together other handlers.
pub struct IronOwnerAuthorizer<A: iron::Handler>(pub A);

/// Use an iron request as an owner authorizer.
///
/// The extension system on requests and responses is used to insert and extract the query and
/// response which makes it possible to leverage irons' builtin wrapper system to build safer
/// and more intuitive implementations (e.g. by reusing existing authorization handlers to
/// enforce user login).
/// ```rust
/// // TODO: example needed for this seemingly more complex but common use case
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
    where F :Fn(&mut iron::Request, AuthenticationRequest) -> Result<(Authentication, Response), OAuthError> + Send + Sync + 'static {
    fn get_owner_authorization(&self, req: &mut iron::Request, auth: AuthenticationRequest)
    -> Result<(Authentication, Response), OAuthError> {
        self(req, auth)
    }
}

impl<A: iron::Handler> GenericOwnerAuthorizer for IronOwnerAuthorizer<A> {
    fn get_owner_authorization(&self, req: &mut iron::Request, auth: AuthenticationRequest)
    -> Result<(Authentication, Response), OAuthError> {
        (&self.0 as &iron::Handler).get_owner_authorization(req, auth)
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
    fn redirect(url: Url) -> Result<Response, OAuthError> {
        let real_url = match iron::Url::from_generic_url(url) {
            Err(_) => return Err(OAuthError::Other("Error parsing redirect target".to_string())),
            Ok(v) => v,
        };
        Ok(Response::with((iron::status::Found, Redirect(real_url))))
    }

    fn text(text: &str) -> Result<Response, OAuthError> {
        Ok(Response::with((iron::status::Ok, text)))
    }

    fn json(data: &str) -> Result<Response, OAuthError> {
        Ok(Response::with((
            iron::status::Ok,
            iron::modifiers::Header(iron::headers::ContentType::json()),
            data,
        )))
    }

    fn as_client_error(self) -> Result<Self, OAuthError> {
        Ok(self)
    }

    fn as_unauthorized(self) -> Result<Self, OAuthError> {
        Ok(self)
    }

    fn with_authorization(self, kind: &str) -> Result<Self, OAuthError> {
        Ok(self)
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
    pub use url::Url;
    pub use code_grant::prelude::*;
    pub use super::{IronGranter, IronOwnerAuthorizer, AuthenticationRequest, Authentication, OAuthError};
}
