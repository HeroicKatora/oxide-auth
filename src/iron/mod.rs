extern crate iron;
extern crate urlencoded;

use super::code_grant::*;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, LockResult, MutexGuard};
use std::ops::DerefMut;
use self::iron::prelude::*;
use self::iron::modifiers::Redirect;
use self::urlencoded::{UrlEncodedBody, UrlEncodedQuery, QueryMap as UQueryMap};

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
    page_handler: Box<OwnerAuthorizer>,
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

/// Process authorization requests from an owner.
///
/// The authorizer can answer requests by indicating authorization progress and returning a result
/// page to display. The page might not get displayed if the answer is already positive but will
/// always be presented to the user-agent when the returning InProgress.
/// Be aware that query parameters will need to be present in the final request as well, as
/// extraction of query parameters can no currently be influenced.
pub trait OwnerAuthorizer: Send + Sync + 'static {
    fn get_owner_authorization(&self, &mut iron::Request, AuthenticationRequest) -> Result<(Authentication, Response), IronError>;
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

fn extract_parameters(params: UQueryMap) -> Result<ClientParameter<'static>, String> {
    let query = params.iter()
        .filter(|&(_, v)| v.len() == 1)
        .map(|(k, v)| (k.clone().into(), v[0].clone().into()))
        .collect::<QueryMap<'static>>();
    decode_query(query)
}

impl<R, A> iron::Handler for IronAuthorizer<R, A> where
    R: Registrar + Send + 'static,
    A: Authorizer + Send + 'static
{
    fn handle<'a>(&'a self, req: &mut iron::Request) -> IronResult<Response> {
        let urlparameters = match req.get::<UrlEncodedQuery>() {
            Err(_) => return Ok(Response::with((iron::status::BadRequest, "Missing valid url encoded parameters"))),
            Ok(res) => res,
        };

        let urldecoded = match extract_parameters(urlparameters) {
            Err(st) => return Ok(Response::with((iron::status::BadRequest, st))),
            Ok(url) => url,
        };

        let mut lockedreg = self.registrar.lock().unwrap();
        let mut locked = self.authorizer.lock().unwrap();
        let mut granter = CodeRef::with(lockedreg.deref_mut(), locked.deref_mut());

        let negotiated = match granter.negotiate(urldecoded.client_id, urldecoded.scope, urldecoded.redirect_url) {
            Err(st) => return Ok(Response::with((iron::status::BadRequest, st))),
            Ok(v) => v
        };

        let auth = AuthenticationRequest{ client_id: negotiated.client_id.to_string(), scope: negotiated.scope.to_string() };
        let owner = match self.page_handler.get_owner_authorization(req, auth)? {
            (Authentication::Failed, _)
                => return Ok(Response::with((iron::status::BadRequest, "Authentication failed"))),
            (Authentication::InProgress, response)
                => return Ok(response),
            (Authentication::Authenticated(v), _) => v,
        };

        let redirect_to = granter.authorize(
            owner.clone().into(),
            negotiated,
            urldecoded.state.clone());

        let real_url = match iron::Url::from_generic_url(redirect_to) {
            Err(_) => return Ok(Response::with((iron::status::InternalServerError, "Error parsing redirect target"))),
            Ok(v) => v,
        };
        Ok(Response::with((iron::status::Found, Redirect(real_url))))
    }
}


impl<A, I> iron::Handler for IronTokenRequest<A, I> where
    A: Authorizer + Send + 'static,
    I: Issuer + Send + 'static
{
    fn handle<'a>(&'a self, req: &mut iron::Request) -> IronResult<Response> {
        use std::borrow::Cow;
        let query = match req.get_ref::<UrlEncodedBody>() {
            Err(_) => return Ok(Response::with((iron::status::BadRequest, "Body not url encoded"))),
            Ok(v) => v,
        };

        fn single_result<'l>(list: &'l Vec<String>) -> Result<&'l str, Cow<'static, str>>{
            if list.len() == 1 { Ok(&list[0]) } else { Err("Invalid parameter".into()) }
        }
        let get_param = |name: &str| query.get(name).ok_or(Cow::Owned("Missing parameter".to_owned() + name)).and_then(single_result);

        let grant_typev = get_param("grant_type").and_then(
            |grant| if grant == "authorization_code" { Ok(grant) } else { Err(Cow::Owned("Invalid grant type".to_owned() + grant)) });
        let client_idv = get_param("client_id");
        let codev = get_param("code");
        let redirect_urlv = get_param("redirect_url");

        let (client, code, redirect_url) = match (grant_typev, client_idv, codev, redirect_urlv) {
            (Err(cause), _, _, _) => return Ok(Response::with((iron::status::BadRequest, cause.as_ref()))),
            (_, Err(cause), _, _) => return Ok(Response::with((iron::status::BadRequest, cause.as_ref()))),
            (_, _, Err(cause), _) => return Ok(Response::with((iron::status::BadRequest, cause.as_ref()))),
            (_, _, _, Err(cause)) => return Ok(Response::with((iron::status::BadRequest, cause.as_ref()))),
            (Ok(_), Ok(client), Ok(code), Ok(redirect))
                => (client, code, redirect)
        };

        let mut authlocked = self.authorizer.lock().unwrap();
        let mut issuelocked = self.issuer.lock().unwrap();
        let mut issuer = IssuerRef::with(authlocked.deref_mut(), issuelocked.deref_mut());

        let token = match issuer.use_code(code.to_string(), client.into(), redirect_url.into()) {
            Err(st) => return Ok(Response::with((iron::status::BadRequest, st.as_ref()))),
            Ok(token) => token,
        };

        Ok(Response::with((iron::status::Ok, token.token + " with refresh " + &token.refresh + " valid until " + &token.until.to_rfc2822())))
    }
}

/// Reexport most useful structs as well as the code_grant core library.
pub mod prelude {
    pub use code_grant::prelude::*;
    pub use super::{IronGranter, AuthenticationRequest, Authentication};
}
