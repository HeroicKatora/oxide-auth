//! Offers bindings for the code_grant module with iron servers.
//!
//! ## Hello world
//!
//! ```no_run
//! # extern crate oxide_auth;
//! # extern crate iron;
//! extern crate router;
//! use oxide_auth::frontends::iron::prelude::*;
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
//!         TokenSigner::new_from_passphrase(passphrase, None));
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

use code_grant::prelude::*;
use code_grant::frontend::{AccessFlow, AuthorizationFlow, GrantFlow, OwnerAuthorizer, WebRequest, WebResponse};
pub use code_grant::frontend::{Authentication, OAuthError};
pub use code_grant::prelude::{PreGrant, Scope};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, LockResult, MutexGuard};
use std::ops::DerefMut;
use std::marker::PhantomData;
use self::iron::{BeforeMiddleware, Handler, IronResult, IronError, Plugin, Url as IronUrl};
use self::iron::headers::{Authorization as AuthHeader, ContentType};
use self::iron::modifiers::Header;
use self::iron::request::Request;
use self::iron::response::Response;
use self::iron::status;
use self::iron::typemap;
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

impl typemap::Key for PreGrant { type Value = PreGrant; }

impl typemap::Key for Authentication { type Value = Authentication; }

/// An owner authorizer for iron requests specifically.
///
/// This bridges between the owner authorizer of the general frontend, whose lifetime is limited to
/// the lifetime of the request, and the configured iron frontend, whose owner authorizer needs
/// to be valid for multiple request lifetimes and `Send` + `Sync` `'static`.
///
/// Two notable implementations exist, one for general functions with the correct parameters and
/// one for encapsulating `Handler` implementations.
pub trait GenericOwnerAuthorizer: Send + Sync + 'static {
    /// Derive a response to the grant request from the web request and internal state.
    fn get_owner_authorization(&self, &mut Request, &PreGrant) -> IronResult<(Authentication, Response)>;
}

/// Wraps an `Handler` for use as an `GenericOwnerAuthorizer`.
///
/// This allows interoperability with other iron libraries. On top of that, one can use the standard
/// middleware facilities to quickly stick together other handlers.
///
/// The extension system on requests and responses is used to insert and extract the query and
/// response which makes it possible to leverage irons' builtin wrapper system to build safer
/// and more intuitive implementations (e.g. by reusing existing authorization handlers to
/// enforce user login).
///
/// ```rust
/// # extern crate oxide_auth;
/// # extern crate urlencoded;
/// # extern crate iron;
/// #
/// # use iron::{IronError, IronResult, Plugin, Request, Response};
/// # use urlencoded::UrlEncodedQuery;
/// # use oxide_auth::code_grant::frontend::Authentication;
/// use oxide_auth::frontends::iron::{IronOwnerAuthorizer, GenericOwnerAuthorizer};
///
/// fn iron_handler(req: &mut Request) -> IronResult<Response> {
///     let query = req.get::<UrlEncodedQuery>()
///         .map_err(|ue| IronError::new(ue, iron::status::BadRequest))?;
///     if query.contains_key("deny") {
///         req.extensions.insert::<Authentication>(Authentication::Failed);
///
///     // Obviously should be replaced with real user authentication, signed cookies or macroons
///     } else if let Some(user) = query.get("user_id") {
///         if user.len() == 1 {
///             req.extensions.insert::<Authentication>(
///                 Authentication::Authenticated(user[1].clone()));
///         } else {
///             req.extensions.insert::<Authentication>(Authentication::Failed);
///         }
///     } else {
///         req.extensions.insert::<Authentication>(Authentication::Failed);
///     }
///     Ok(Response::with(iron::status::Ok))
/// }
///
/// const iron_owner_authorizer: &GenericOwnerAuthorizer = &IronOwnerAuthorizer(iron_handler);
/// # fn main() {}
/// ```
pub struct IronOwnerAuthorizer<A: Handler>(pub A);

impl GenericOwnerAuthorizer for Handler {
    fn get_owner_authorization(&self, req: &mut Request, auth: &PreGrant)
    -> IronResult<(Authentication, Response)> {
        req.extensions.insert::<PreGrant>(auth.clone());
        let response = self.handle(req)?;
        match req.extensions.get::<Authentication>() {
            None => return Ok((Authentication::Failed, Response::with((status::InternalServerError, "No authentication response")))),
            Some(v) => return Ok((v.clone(), response)),
        };
    }
}

impl<F> GenericOwnerAuthorizer for F
    where F :Fn(&mut Request, &PreGrant) -> Result<(Authentication, Response), OAuthError> + Send + Sync + 'static {
    fn get_owner_authorization(&self, req: &mut Request, auth: &PreGrant)
    -> IronResult<(Authentication, Response)> {
        self(req, auth).map_err(|o| o.into())
    }
}

impl<A: Handler> GenericOwnerAuthorizer for IronOwnerAuthorizer<A> {
    fn get_owner_authorization(&self, req: &mut Request, auth: &PreGrant)
    -> IronResult<(Authentication, Response)> {
        (&self.0 as &Handler).get_owner_authorization(req, auth)
    }
}

struct SpecificOwnerAuthorizer<'l, 'a, 'b: 'a>(&'l GenericOwnerAuthorizer, PhantomData<Request<'a, 'b>>);

impl<'l, 'a, 'b: 'a> OwnerAuthorizer for SpecificOwnerAuthorizer<'l, 'a, 'b> {
    type Request = Request<'a, 'b>;
    fn get_owner_authorization(&self, req: &mut Self::Request, auth: &PreGrant)
    -> IronResult<(Authentication, Response)> {
        self.0.get_owner_authorization(req, auth)
    }
}

impl<'a, 'b> WebRequest for Request<'a, 'b> {
    type Response = Response;
    type Error = IronError;

    fn query(&mut self) -> Result<Cow<HashMap<String, Vec<String>>>, ()> {
        match self.get_ref::<UrlEncodedQuery>() {
            Ok(query) => Ok(Cow::Borrowed(query)),
            Err(_) => Err(()),
        }
    }

    fn urlbody(&mut self) -> Result<Cow<HashMap<String, Vec<String>>>, ()> {
        match self.get_ref::<UrlEncodedBody>() {
            Ok(query) => Ok(Cow::Borrowed(query)),
            Err(_) => Err(()),
        }
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
        let real_url = match IronUrl::from_generic_url(url) {
            Err(_) => return Err(IronError::new(OAuthError::InternalCodeError(),
                status::InternalServerError)),
            Ok(v) => v,
        };
        Ok(Response::with((status::Found, Redirect(real_url))))
    }

    fn text(text: &str) -> Result<Response, IronError> {
        Ok(Response::with((status::Ok, text)))
    }

    fn json(data: &str) -> Result<Response, IronError> {
        Ok(Response::with((
            status::Ok,
            Header(ContentType::json()),
            data,
        )))
    }

    fn as_client_error(mut self) -> Result<Self, IronError> {
        self.status = Some(status::BadRequest);
        Ok(self)
    }

    fn as_unauthorized(mut self) -> Result<Self, IronError> {
        self.status = Some(status::Unauthorized);
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
    /// Construct from all internally used primites.
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
        IronError::new(this, status::Unauthorized)
    }
}

impl<PH, R, A> Handler for IronAuthorizer<PH, R, A> where
    PH: GenericOwnerAuthorizer + Send + Sync + 'static,
    R: Registrar + Send + 'static,
    A: Authorizer + Send + 'static
{
    fn handle<'a>(&'a self, req: &mut Request) -> IronResult<Response> {
        let mut locked_registrar = self.registrar.lock().unwrap();
        let mut locked_authorizer = self.authorizer.lock().unwrap();
        let authorization_flow = AuthorizationFlow::new(
            locked_registrar.deref_mut(), locked_authorizer.deref_mut());

        let handler = SpecificOwnerAuthorizer(self.page_handler.as_ref(), PhantomData);
        authorization_flow.handle(req, &handler)
    }
}


impl<R, A, I> Handler for IronTokenRequest<R, A, I> where
    R: Registrar + Send + 'static,
    A: Authorizer + Send + 'static,
    I: Issuer + Send + 'static
{
    fn handle<'a>(&'a self, request: &mut Request) -> IronResult<Response> {
        let mut locked_registrar = self.registrar.lock().unwrap();
        let mut locked_authorizer = self.authorizer.lock().unwrap();
        let mut locked_issuer = self.issuer.lock().unwrap();
        GrantFlow::new(
            locked_registrar.deref_mut(),
            locked_authorizer.deref_mut(),
            locked_issuer.deref_mut())
            .handle(request)
    }
}

impl<I> BeforeMiddleware for IronGuard<I> where
    I: Issuer + Send + 'static
{
    fn before(&self, request: &mut Request) -> IronResult<()> {
        let mut locked_issuer = self.issuer.lock().unwrap();
        AccessFlow::new(locked_issuer.deref_mut(), &self.scopes)
            .handle(request).into()
    }
}

/// Reexport most useful structs as well as the code_grant core library.
pub mod prelude {
    pub use url::Url;
    pub use code_grant::prelude::*;
    pub use super::{IronGranter, IronOwnerAuthorizer, PreGrant, Authentication, OAuthError};
}
