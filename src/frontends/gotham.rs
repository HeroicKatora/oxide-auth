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
use std::sync::{Arc, Mutex};

#[derive(StateData, Clone)]
pub struct GothamGranter {
    pub registrar: Arc<Mutex<Registrar + Send>>,
    pub authorizer: Arc<Mutex<Authorizer + Send>>,
    pub issuer: Arc<Mutex<Issuer + Send>>,
}

#[derive(StateData)]
pub struct OAuthRequest(Request);

#[derive(Clone, NewMiddleware)]
pub struct OAuthStateDataMiddleware {
    granter: GothamGranter,
}

impl OAuthStateDataMiddleware {
    pub fn new(granter: GothamGranter) -> Self {
        Self { granter: granter }
    }
}

impl Middleware for OAuthStateDataMiddleware {
    fn call<Chain>(self, mut state: State, chain: Chain) -> Box<HandlerFuture>
    where
        Chain: FnOnce(State) -> Box<HandlerFuture> + 'static,
    {
        let f = state.take::<Body>().concat2().then(move |chunk| {
            match chunk {
                Ok(valid_body) => {
                    let method = state.borrow::<Method>().clone();
                    let uri = state.borrow::<Uri>().clone();
                    let headers = state.borrow::<Headers>().clone();

                    // Reconstruct the hyper request for OAuthRequest.
                    let mut request = Request::new(method.clone(), uri.clone());
                    let body = valid_body.to_vec();
                    request.set_body(body.clone());
                    for header in headers.iter() {
                        request.headers_mut().set_raw(
                            header.name().to_owned(),
                            header.raw().clone()
                        );
                    }

                    state.put(OAuthRequest(request));
                    state.put(self.granter);
                    // Put body back into state for the handler.
                    state.put::<Body>(body.into());

                    chain(state)
                },
                Err(e) => Box::new(future::err((state, e.into_handler_error()))),
            }
        });

        Box::new(f)
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
        let oath = state.take::<OAuthRequest>();
        let f = oath.guard().then(move |result| {
            match result {
                Ok(guard) => {
                    let gotham_granter = state.take::<GothamGranter>();
                    let mut issuer = gotham_granter.issuer.lock().unwrap();
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

impl OAuthRequest {
    pub fn authorization_code(self, state: &State) -> AuthorizationCodeRequest {
        let OAuthRequest(request) = self;

        AuthorizationCodeRequest {
            request: Some(request),
            state: state,
        }
    }

    pub fn access_token(self, body: Body) -> GrantRequest {
        let OAuthRequest(request) = self;

        GrantRequest {
            request: Some(request),
            body: Some(body),
        }
    }

    pub fn guard(self) -> GuardRequest {
        let OAuthRequest(request) = self;

        GuardRequest {
            request: Some(request),
        }
    }
}

pub struct AuthorizationCodeRequest<'a> {
    request: Option<Request>,
    state: &'a State,
}

pub struct GrantRequest {
    request: Option<Request>,
    body: Option<Body>,
}

pub struct GuardRequest {
    request: Option<Request>,
}

pub struct ReadyAuthorizationCodeRequest<'a> {
    request: ResolvedRequest,
    state: &'a State,
}
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

struct ResolvedOwnerAuthorization<'a, A> {
    handler: A,
    state: &'a State,
}

impl<'a, A> OwnerAuthorizer<ResolvedRequest> for ResolvedOwnerAuthorization<'a, A>
where A: Fn(&Request, &State, &PreGrant) -> OwnerAuthorization<Response> {
    fn check_authorization(self, request: ResolvedRequest, grant: &PreGrant) -> OwnerAuthorization<Response> {
        (self.handler)(&request.request, self.state, grant)
    }
}

impl<'a> Future for AuthorizationCodeRequest<'a> {
    type Item = ReadyAuthorizationCodeRequest<'a>;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let resolved = ResolvedRequest::headers_only(self.request.take().unwrap());
        Ok(Async::Ready(ReadyAuthorizationCodeRequest {request: resolved, state: self.state}))
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

impl<'a> ReadyAuthorizationCodeRequest<'a> {
    pub fn handle<A>(self, flow: AuthorizationFlow, authorizer: A)-> Result<Response, OAuthError>
    where
        A: Fn(&Request, &State, &PreGrant) -> OwnerAuthorization<Response>
    {
        flow.handle(self.request).complete(ResolvedOwnerAuthorization { handler: authorizer, state: self.state })
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
