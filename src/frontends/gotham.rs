extern crate hyper;
extern crate mime;
extern crate futures;
extern crate gotham;
extern crate serde_urlencoded;

use super::dev::*;
pub use code_grant::frontend::{AccessFlow, AuthorizationFlow, GrantFlow};
pub use code_grant::frontend::{OwnerAuthorization, OwnerAuthorizer};
pub use code_grant::frontend::{OAuthError, AuthorizationResult};
pub use code_grant::prelude::*;

use self::hyper::{StatusCode, Request, Response, Method, Uri, Headers, Body};
use self::hyper::header::{Authorization, ContentLength, ContentType, Location};
use gotham::state::State;
use gotham::middleware::Middleware;
use gotham::handler::{HandlerFuture, IntoHandlerError};

use self::futures::{Async, Poll, Stream};
pub use self::futures::{Future, future};

use std::collections::HashMap;
use std::sync::{Arc, Mutex, LockResult, MutexGuard};

#[derive(StateData, Clone)]
pub struct GothamOauthProvider {
    registrar: Arc<Mutex<Registrar + Send>>,
    authorizer: Arc<Mutex<Authorizer + Send>>,
    issuer: Arc<Mutex<Issuer + Send>>,
}
impl GothamOauthProvider {
    pub fn new<R, A, I>(registrar: R, data: A, issuer: I) -> Self where
        R: Registrar + Send + 'static,
        A: Authorizer + Send + 'static,
        I: Issuer + Send + 'static
    {
        Self {
            registrar: Arc::new(Mutex::new(registrar)),
            authorizer: Arc::new(Mutex::new(data)),
            issuer: Arc::new(Mutex::new(issuer)),
        }
    }

    /// Thread-safely access the underlying registrar, which is responsible for client registrarion.
    pub fn registrar(&self) -> LockResult<MutexGuard<Registrar + Send + 'static>> {
        self.registrar.lock()
    }

    /// Thread-safely access the underlying authorizer, which builds and holds authorization codes.
    pub fn authorizer(&self) -> LockResult<MutexGuard<Authorizer + Send + 'static>> {
        self.authorizer.lock()
    }

    /// Thread-safely access the underlying issuer, which builds and holds access tokens.
    pub fn issuer(&self) -> LockResult<MutexGuard<Issuer + Send + 'static>> {
        self.issuer.lock()
    }

    fn request_from_state(&self, state: &State) -> Request {
        let method = state.borrow::<Method>().clone();
        let uri = state.borrow::<Uri>().clone();
        let headers = state.borrow::<Headers>().clone();

        let mut request = Request::new(method.clone(), uri.clone());
        for header in headers.iter() {
            request.headers_mut().set_raw(
                header.name().to_owned(),
                header.raw().clone()
            );
        }

        request
    }

    pub fn authorization_code(&self, state: &State) -> AuthorizationCodeRequest {
        AuthorizationCodeRequest {
            request: Some(self.request_from_state(&state)),
        }
    }

    pub fn access_token(&self, state: &State, body: Body) -> GrantRequest {
        GrantRequest {
            request: Some(self.request_from_state(&state)),
            body: Some(body),
        }
    }

    pub fn guard(&self, state: &State) -> GuardRequest {
        GuardRequest {
            request: Some(self.request_from_state(&state)),
        }
    }
}

#[derive(Clone, NewMiddleware)]
pub struct OAuthStateDataMiddleware {
    provider: GothamOauthProvider,
}

impl OAuthStateDataMiddleware {
    pub fn new(provider: GothamOauthProvider) -> Self {
        Self { provider: provider }
    }
}

impl Middleware for OAuthStateDataMiddleware {
    fn call<Chain>(self, mut state: State, chain: Chain) -> Box<HandlerFuture>
    where
        Chain: FnOnce(State) -> Box<HandlerFuture> + 'static,
    {
        state.put(self.provider);

        chain(state)
    }
}

#[derive(Clone, NewMiddleware)]
pub struct OAuthGuardMiddleware {
    scopes: Vec<Scope>,
}

impl OAuthGuardMiddleware {
    pub fn new(scopes: Vec<Scope>) -> Self {
        Self { scopes: scopes }
    }
}

impl Middleware for OAuthGuardMiddleware {
    fn call<Chain>(self, mut state: State, chain: Chain) -> Box<HandlerFuture>
    where
        Chain: FnOnce(State) -> Box<HandlerFuture> + 'static,
    {
        let oauth = state.borrow::<GothamOauthProvider>().clone();
        let guard_request = oauth.guard(&state);
        let f = guard_request.then(move |result| {
            match result {
                Ok(guard) => {
                    let mut issuer = oauth.issuer().unwrap();
                    let flow = AccessFlow::new(&mut *issuer, self.scopes.as_slice());
                    match guard.handle(flow) {
                        Ok(_) => chain(state),
                        Err(e) => Box::new(future::err((state, e.into_handler_error())))
                    }
                },
                Err(e) => Box::new(future::err((state, e.into_handler_error()))),
            }
        });

        Box::new(f)
    }
}

pub struct ResolvedRequest {
    request: Request,
    authorization: Result<Option<String>, ()>,
    query: Option<HashMap<String, String>>,
    body: Option<HashMap<String, String>>,
}

pub struct AuthorizationCodeRequest {
    request: Option<Request>,
}

pub struct GrantRequest {
    request: Option<Request>,
    body: Option<Body>,
}

pub struct GuardRequest {
    request: Option<Request>,
}

pub struct ReadyAuthorizationCodeRequest(ResolvedRequest);
pub struct ReadyGrantRequest(ResolvedRequest);
pub struct ReadyGuardRequest(ResolvedRequest);

impl WebRequest for ResolvedRequest {
    type Error = OAuthError;
    type Response = Response;

    fn query(&mut self) -> Result<QueryParameter, ()> {
        self.query.as_ref().map(|query| QueryParameter::SingleValue(
            SingleValueQuery::StringValue(Cow::Borrowed(query))))
            .ok_or(())
    }

    fn urlbody(&mut self) -> Result<QueryParameter, ()> {
        self.body.as_ref().map(|body| QueryParameter::SingleValue(
            SingleValueQuery::StringValue(Cow::Borrowed(body))))
            .ok_or(())
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, ()>{
        match &self.authorization {
            &Ok(Some(ref string)) => Ok(Some(Cow::Borrowed(string))),
            &Ok(None) => Ok(None),
            &Err(_) => Err(())
        }
    }
}

impl WebResponse for Response {
    type Error = OAuthError;

    fn redirect(url: Url) -> Result<Self, Self::Error> {
        let response = Response::new()
            .with_header(Location::new(url.into_string()))
            .with_status(StatusCode::Found);

        Ok(response)
    }

    fn text(text: &str) -> Result<Self, Self::Error> {
        let response = Response::new()
            .with_header(ContentLength(text.len() as u64))
            .with_header(ContentType(mime::TEXT_PLAIN))
            .with_status(StatusCode::Ok)
            .with_body(text.to_owned());

        Ok(response)
    }

    fn json(data: &str) -> Result<Self, Self::Error> {
        let response = Response::new()
            .with_header(ContentLength(data.len() as u64))
            .with_header(ContentType(mime::APPLICATION_JSON))
            .with_status(StatusCode::Ok)
            .with_body(data.to_owned());

        Ok(response)
    }

    fn as_client_error(mut self) -> Result<Self, Self::Error> {
        self.set_status(StatusCode::BadRequest);
        Ok(self)
    }

    /// Set the response status to 401
    fn as_unauthorized(mut self) -> Result<Self, Self::Error> {
        self.set_status(StatusCode::Unauthorized);
        Ok(self)
    }

    /// Add an `WWW-Authenticate` header
    fn with_authorization(mut self, kind: &str) -> Result<Self, Self::Error> {
        self.headers_mut().set_raw("WWW-Authenticate", vec![kind.as_bytes().to_vec()]);
        Ok(self)
    }

}

impl ResolvedRequest {
    fn headers_only(request: Request) -> Self {
        let authorization = match request.headers().get::<Authorization<String>>() {
            None => Ok(None),
            Some(header) => Ok(Some(format!("{}", header))),
        };

        let query = request.query().and_then(|query_string| {
            serde_urlencoded::from_str::<HashMap<String, String>>(query_string).ok()
        });

        ResolvedRequest {
            request: request,
            authorization: authorization,
            query: query,
            body: None,
        }
    }

    fn with_body(request: Request, body: HashMap<String, String>) -> Self {
        let mut resolved = Self::headers_only(request);
        resolved.body = Some(body);
        resolved
    }
}

struct ResolvedOwnerAuthorization<A> {
    handler: A,
}

impl<A> OwnerAuthorizer<ResolvedRequest> for ResolvedOwnerAuthorization<A>
where
    A: Fn(&Request, &PreGrant) -> OwnerAuthorization<Response>
{
    fn check_authorization(self, request: ResolvedRequest, grant: &PreGrant) -> OwnerAuthorization<Response> {
        (self.handler)(&request.request, grant)
    }
}

impl Future for AuthorizationCodeRequest {
    type Item = ReadyAuthorizationCodeRequest;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let resolved = ResolvedRequest::headers_only(self.request.take().unwrap());
        Ok(Async::Ready(ReadyAuthorizationCodeRequest(resolved)))
    }
}


impl Future for GrantRequest {
    type Item = ReadyGrantRequest;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.body.take().unwrap().poll() {
            Ok(Async::Ready(body)) => {
                body.and_then(|valid_body| {
                    String::from_utf8(valid_body.to_vec()).ok()
                })
                .and_then(|body_string| {
                    serde_urlencoded::from_str::<HashMap<String, String>>(body_string.as_str()).ok()
                })
                .and_then(|decoded_body| {
                    let resolved = ResolvedRequest::with_body(self.request.take().unwrap(), decoded_body);
                    Some(Async::Ready(ReadyGrantRequest(resolved)))
                })
                .ok_or_else(|| OAuthError::AccessDenied)
            },
            Ok(Async::NotReady) => Ok(Async::NotReady),

            // Not a valid url encoded body
            Err(_) => Err(OAuthError::AccessDenied),
        }
    }
}

impl Future for GuardRequest {
    type Item = ReadyGuardRequest;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let resolved = ResolvedRequest::headers_only(self.request.take().unwrap());
        Ok(Async::Ready(ReadyGuardRequest(resolved)))
    }
}

impl ReadyAuthorizationCodeRequest {
    pub fn handle<A>(self, flow: AuthorizationFlow, authorizer: A)-> Result<Response, OAuthError>
    where
        A: Fn(&Request, &PreGrant) -> OwnerAuthorization<Response>
    {
        flow.handle(self.0).complete(ResolvedOwnerAuthorization { handler: authorizer })
    }
}

impl ReadyGrantRequest {
    pub fn handle(self, flow: GrantFlow) -> Result<Response, OAuthError> {
        flow.handle(self.0)
    }
}

impl ReadyGuardRequest {
    pub fn handle(self, flow: AccessFlow) -> Result<(), OAuthError> {
        flow.handle(self.0)
    }
}
