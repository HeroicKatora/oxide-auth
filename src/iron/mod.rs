//! Offers bindings for the code_grant module with iron servers.
//!
//! ## Hello world
//!
//! ```no_run
//! # extern crate oxide_auth;
//! # extern crate iron;
//! extern crate router;
//! use oxide_auth::iron::prelude::*;
//! use iron::prelude::*;
//!
//! use std::thread;
//! use iron::modifier::Modifier;
//! use router::Router;
//!
//! /// Example of a main function of a iron server supporting oauth.
//! pub fn main() {
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
//!     let client = Client::public("LocalClient", // Client id
//!         "http://localhost:8021/endpoint".parse().unwrap(), // Redirection url
//!         "default".parse().unwrap()); // Allowed client scope
//!     ohandler.registrar().unwrap().register_client(client);
//!
//!     // Create a router and bind the relevant pages
//!     let mut router = Router::new();
//!     router.get("/authorize", ohandler.authorize(handle_get), "authorize");
//!     router.post("/authorize", ohandler.authorize(IronOwnerAuthorizer(handle_post)),
//!         "authorize");
//!     router.post("/token", ohandler.token(), "token");
//!
//!     let mut protected = iron::Chain::new(|_: &mut Request| {
//!         Ok(Response::with((iron::status::Ok, "Hello World!")))
//!     });
//!     // Set up a protected resource, only accessible with a token with `default scope`.
//!     protected.link_before(ohandler.guard(vec!["default".parse::<Scope>().unwrap()]));
//!     // Instead of an error, show a warning and instructions
//!     protected.link_after(HelpfulAuthorizationError());
//!     router.get("/", protected, "protected");
//!
//!     // Start the server
//!     let server = thread::spawn(||
//!         iron::Iron::new(router).http("localhost:8020").unwrap());
//!
//!     server.join().expect("Failed to run");
//! }
//!
//! /// This should display a page to the user asking for his permission to proceed.
//! /// You can use the Response in Ok to achieve this.
//! fn handle_get(_: &mut Request, auth: &PreGrant) -> Result<(Authentication, Response), OAuthError> {
//!     unimplemented!();
//! }
//!
//! /// This shows the second style of authentication handler, a iron::Handler compatible form.
//! /// Allows composition with other libraries or frameworks built around iron.
//! fn handle_post(req: &mut Request) -> IronResult<Response> {
//!     unimplemented!();
//! }
//!
//! /// Show a message to unauthorized requests of the protected resource.
//! struct HelpfulAuthorizationError();
//!
//! impl iron::middleware::AfterMiddleware for HelpfulAuthorizationError {
//!     fn catch(&self, _: &mut Request, err: iron::IronError) -> IronResult<Response> {
//!         if !err.error.is::<OAuthError>() {
//!            return Err(err);
//!         }
//!         let mut response = err.response;
//!         let text =
//!             "<html>
//! 	    This page is only accessible with an oauth token, scope <em>default</em>.
//!             </html>";
//!         text.modify(&mut response);
//!         iron::modifiers::Header(iron::headers::ContentType::html()).modify(&mut response);
//!         Ok(response)
//!     }
//! }
//!
//! ```

extern crate iron;
extern crate urlencoded;

use super::code_grant::prelude::*;
use super::code_grant::frontend::{AccessFlow, AuthorizationFlow, GrantFlow, OwnerAuthorizer, WebRequest, WebResponse};
pub use super::code_grant::frontend::{Authentication, OAuthError};
pub use super::code_grant::Scope;
pub use super::code_grant::prelude::PreGrant;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, LockResult, MutexGuard};
use std::ops::DerefMut;
use std::marker::PhantomData;
use self::iron::prelude::*;
use self::iron::headers::{Authorization as AuthHeader};
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
pub struct IronTokenRequest<R, A, I> where
    R: Registrar + Send + 'static,
    A: Authorizer + Send + 'static,
    I: Issuer + Send + 'static
{
    registrar: Arc<Mutex<R>>,
    authorizer: Arc<Mutex<A>>,
    issuer: Arc<Mutex<I>>,
}

/// Protects a resource as an AroundMiddleware
pub struct IronGuard<I> where
    I: Issuer + Send + 'static
{
    scopes: Vec<Scope>,
    issuer: Arc<Mutex<I>>,
}

impl iron::typemap::Key for PreGrant<'static> { type Value = PreGrant<'static>; }

impl iron::typemap::Key for Authentication { type Value = Authentication; }

pub trait GenericOwnerAuthorizer {
    fn get_owner_authorization(&self, &mut iron::Request, &PreGrant) -> IronResult<(Authentication, iron::Response)>;
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
    fn get_owner_authorization(&self, req: &mut iron::Request, auth: &PreGrant)
    -> IronResult<(Authentication, Response)> {
        let owned_auth = PreGrant::<'static> {
            client_id: Cow::Owned(auth.client_id.as_ref().to_string()),
            redirect_url: Cow::Owned(auth.redirect_url.as_ref().clone()),
            scope: Cow::Owned(auth.scope.as_ref().clone()),
        };
        req.extensions.insert::<PreGrant>(owned_auth);
        let response = self.handle(req)?;
        match req.extensions.get::<Authentication>() {
            None => return Ok((Authentication::Failed, Response::with((iron::status::InternalServerError, "No authentication response")))),
            Some(v) => return Ok((v.clone(), response)),
        };
    }
}

impl<F> GenericOwnerAuthorizer for F
    where F :Fn(&mut iron::Request, &PreGrant) -> Result<(Authentication, Response), OAuthError> + Send + Sync + 'static {
    fn get_owner_authorization(&self, req: &mut iron::Request, auth: &PreGrant)
    -> IronResult<(Authentication, Response)> {
        self(req, auth).map_err(|o| o.into())
    }
}

impl<A: iron::Handler> GenericOwnerAuthorizer for IronOwnerAuthorizer<A> {
    fn get_owner_authorization(&self, req: &mut iron::Request, auth: &PreGrant)
    -> IronResult<(Authentication, Response)> {
        (&self.0 as &iron::Handler).get_owner_authorization(req, auth)
    }
}

struct SpecificOwnerAuthorizer<'l, 'a, 'b: 'a>(&'l GenericOwnerAuthorizer, PhantomData<iron::Request<'a, 'b>>);

impl<'l, 'a, 'b: 'a> OwnerAuthorizer for SpecificOwnerAuthorizer<'l, 'a, 'b> {
    type Request = iron::Request<'a, 'b>;
    fn get_owner_authorization(&self, req: &mut Self::Request, auth: &PreGrant)
    -> IronResult<(Authentication, Response)> {
        self.0.get_owner_authorization(req, auth)
    }
}

impl<'a, 'b> WebRequest for iron::Request<'a, 'b> {
    type Response = Response;
    type Error = IronError;

    fn query(&mut self) -> Result<HashMap<String, Vec<String>>, ()> {
        self.get::<UrlEncodedQuery>().map_err(|_| ())
    }

    fn urlbody(&mut self) -> Result<&HashMap<String, Vec<String>>, ()> {
        self.get_ref::<UrlEncodedBody>().map_err(|_| ())
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, ()> {
        match self.headers.get::<AuthHeader<String>>() {
            None => Ok(None),
            Some(hdr) => Ok(Some(Cow::Borrowed(&hdr))),
        }
    }
}

impl WebResponse for Response {
    type Error = IronError;

    fn redirect(url: Url) -> Result<Response, IronError> {
        let real_url = match iron::Url::from_generic_url(url) {
            Err(_) => return Err(IronError::new(OAuthError::InternalCodeError(),
                iron::status::InternalServerError)),
            Ok(v) => v,
        };
        Ok(Response::with((iron::status::Found, Redirect(real_url))))
    }

    fn text(text: &str) -> Result<Response, IronError> {
        Ok(Response::with((iron::status::Ok, text)))
    }

    fn json(data: &str) -> Result<Response, IronError> {
        Ok(Response::with((
            iron::status::Ok,
            iron::modifiers::Header(iron::headers::ContentType::json()),
            data,
        )))
    }

    fn as_client_error(mut self) -> Result<Self, IronError> {
        self.status = Some(iron::status::BadRequest);
        Ok(self)
    }

    fn as_unauthorized(mut self) -> Result<Self, IronError> {
        self.status = Some(iron::status::Unauthorized);
        Ok(self)
    }

    fn with_authorization(mut self, kind: &str) -> Result<Self, IronError> {
        self.headers.set_raw("WWW-Authenticate", vec![kind.as_bytes().to_vec()]);
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

    /// Create an authorization code endpoint.
    pub fn authorize<H: GenericOwnerAuthorizer + Send + Sync>(&self, page_handler: H) -> IronAuthorizer<H, R, A> {
        IronAuthorizer {
            authorizer: self.authorizer.clone(),
            page_handler: Box::new(page_handler),
            registrar: self.registrar.clone() }
    }

    /// Create an access token endpoint.
    pub fn token(&self) -> IronTokenRequest<R, A, I> {
        IronTokenRequest {
            registrar: self.registrar.clone(),
            authorizer: self.authorizer.clone(),
            issuer: self.issuer.clone() }
    }

    /// Create a BeforeMiddleware capable of guarding other resources.
    pub fn guard<T>(&self, scopes: T) -> IronGuard<I> where T: IntoIterator<Item=Scope> {
        IronGuard { issuer: self.issuer.clone(), scopes: scopes.into_iter().collect() }
    }

    /// Thread-safely access the underlying registrar, which is responsible for client registrarion.
    pub fn registrar(&self) -> LockResult<MutexGuard<R>> {
        self.registrar.lock()
    }

    /// Thread-safely access the underlying authorizer, which builds and holds authorization codes.
    pub fn authorizer(&self) -> LockResult<MutexGuard<A>> {
        self.authorizer.lock()
    }

    /// Thread-safely access the underlying issuer, which builds and holds access tokens.
    pub fn issuer(&self) -> LockResult<MutexGuard<I>> {
        self.issuer.lock()
    }
}

impl From<OAuthError> for IronError {
    fn from(this: OAuthError) -> IronError {
        IronError::new(this, iron::status::Unauthorized)
    }
}

impl<PH, R, A> iron::Handler for IronAuthorizer<PH, R, A> where
    PH: GenericOwnerAuthorizer + Send + Sync + 'static,
    R: Registrar + Send + 'static,
    A: Authorizer + Send + 'static
{
    fn handle<'a>(&'a self, req: &mut iron::Request) -> IronResult<Response> {
        let prepared = AuthorizationFlow::prepare(req)?;

        let mut locked_registrar = self.registrar.lock().unwrap();
        let mut locked_authorizer = self.authorizer.lock().unwrap();
        let code = CodeRef::with(locked_registrar.deref_mut(), locked_authorizer.deref_mut());

        let handler = SpecificOwnerAuthorizer(self.page_handler.as_ref(), PhantomData);
        AuthorizationFlow::handle(code, prepared, &handler)
    }
}


impl<R, A, I> iron::Handler for IronTokenRequest<R, A, I> where
    R: Registrar + Send + 'static,
    A: Authorizer + Send + 'static,
    I: Issuer + Send + 'static
{
    fn handle<'a>(&'a self, req: &mut iron::Request) -> IronResult<Response> {
        let prepared = GrantFlow::prepare(req)?;

        let mut locked_registrar = self.registrar.lock().unwrap();
        let mut locked_authorizer = self.authorizer.lock().unwrap();
        let mut locked_issuer = self.issuer.lock().unwrap();
        let issuer = IssuerRef::with(
            locked_registrar.deref_mut(),
            locked_authorizer.deref_mut(),
            locked_issuer.deref_mut());

        GrantFlow::handle(issuer, prepared)
    }
}

impl<I> iron::BeforeMiddleware for IronGuard<I> where
    I: Issuer + Send + 'static
{
    fn before(&self, request: &mut Request) -> IronResult<()> {
        let prepared = AccessFlow::prepare(request)?;

        let mut locked_issuer = self.issuer.lock().unwrap();
        let guard = GuardRef::with(locked_issuer.deref_mut(), &self.scopes);

        let ok = AccessFlow::handle(guard, prepared)?;
        Ok(ok)
    }
}

/// Reexport most useful structs as well as the code_grant core library.
pub mod prelude {
    pub use url::Url;
    pub use code_grant::prelude::*;
    pub use super::{IronGranter, IronOwnerAuthorizer, PreGrant, Authentication, OAuthError};
}
