use std::borrow::Cow;
use std::cell::RefCell;

use primitives::authorizer::Authorizer;
use primitives::issuer::{Issuer, IssuedToken};
use primitives::registrar::{BoundClient, ClientUrl, Registrar, RegistrarError, PreGrant};
use primitives::scope::Scope;
use primitives::grant::Grant;
use endpoint::{AccessTokenFlow, AuthorizationFlow, ResourceFlow};
use endpoint::{OwnerSolicitor, OwnerConsent, OAuthError, Scopes, WebRequest, WebResponse};
use frontends::simple::endpoint::{Error as SimpleError, Generic, Vacant};

use super::message as m;

use super::actix::{Addr, MailboxError, Message, Recipient};
use super::actix::dev::RecipientRequest;
use super::futures::{Async, Future, Poll};
use super::AsActor;

/// Run an authorization code request asynchonously using actor primitives.
///
/// Due to limitiations with the underlying primitives not yet being fully written with async in
/// mind, there are no extensions and no custom `Endpoint` representations.
pub fn authorization<R, A, S, W>(
    registrar: Addr<AsActor<R>>,
    authorizer: Addr<AsActor<A>>,
    solicitor: S,
    request: W,
    response: W::Response
)
    -> Box<dyn Future<Item=W::Response, Error=W::Error> + 'static>
where
    R: Registrar + 'static,
    A: Authorizer + 'static,
    S: OwnerSolicitor<W> + 'static,
    W: WebRequest + 'static,
    W::Error: From<OAuthError>,
    W::Response: 'static,
{
    Box::new(AuthorizationFuture {
        registrar: RegistrarProxy::new(registrar),
        authorizer: AuthorizerProxy::new(authorizer),
        solicitor,
        request,
        response: Some(response),
    })
}

/// Run an access token request asynchonously using actor primitives.
///
/// Due to limitiations with the underlying primitives not yet being fully written with async in
/// mind, there are no extensions and no custom `Endpoint` representations.
pub fn access_token<R, A, I, W>(
    registrar: Addr<AsActor<R>>,
    authorizer: Addr<AsActor<A>>,
    issuer: Addr<AsActor<I>>,
    request: W,
    response: W::Response
)
    -> Box<dyn Future<Item=W::Response, Error=W::Error> + 'static>
where
    R: Registrar + 'static,
    A: Authorizer + 'static,
    I: Issuer + 'static,
    W: WebRequest + 'static,
    W::Error: From<OAuthError>,
    W::Response: 'static,
{
    Box::new(AccessTokenFuture {
        registrar: RegistrarProxy::new(registrar),
        authorizer: AuthorizerProxy::new(authorizer),
        issuer: IssuerProxy::new(issuer),
        request,
        response: Some(response),
    })
}


/// Test resource access asynchonously against actor primitives.
///
/// Due to limitiations with the underlying primitives not yet being fully written with async in
/// mind, there are no extensions and no custom `Endpoint` representations.
pub fn resource<I, W, C>(
    issuer: Addr<AsActor<I>>,
    scopes: C,
    request: W,
    response: W::Response
)
    -> Box<dyn Future<Item=Grant, Error=ResourceProtection<W::Response>> + 'static>
where
    I: Issuer + 'static,
    C: Scopes<W> + 'static,
    W: WebRequest + 'static,
    W::Error: From<OAuthError>,
    W::Response: 'static,
{
    Box::new(ResourceFuture {
        issuer: IssuerProxy::new(issuer),
        scopes,
        request,
        response: Some(response),
    })
}

/// A wrapper around a result allowing more specific interpretation.
///
/// Simplifies trait semantics while also providing additional documentation on the semantics of
/// each variant. Conversion to a standard `Result` is of course easily possible.
pub enum ResourceProtection<W: WebResponse> {
    /// The error response to the failed access should be based on this.
    ///
    /// Ensures that the `WWW-Authenticate` header is set on the response and also has the status
    /// code already set. While you should use this as a nice helper, it isn't exactly mandatory to
    /// actually send a response based on this. Just don't allow access to the underlying resource.
    Respond(W),

    /// Something went wrong while checking access.
    ///
    /// This is an internal server error (or a library issue) but it's not always wise to directly
    /// indicate this to clients. The `OAuthError` variants help with this and `OAuthFailure` also
    /// provides some sensible choices.
    Error(W::Error),
}

struct Buffer<M> 
where 
    M: Message + Send + 'static,
    M::Result: Send + Clone + 'static,
{
    recipient: Recipient<M>,
    state: BufferState<M>,
}

enum BufferState<M> 
where 
    M: Message + Send + 'static,
    M::Result: Send + Clone + 'static,
{
    NotSent,
    NotYet(RecipientRequest<M>),
    Received(M::Result),
    Consumed(M::Result),
    Error(MailboxError),
    Poison,
}

/// Proxy a single type of request each as a registrar returning errors.
struct RegistrarProxy {
    bound: RefCell<Buffer<m::BoundRedirect>>,
    negotiate: RefCell<Buffer<m::Negotiate>>,
    check: RefCell<Buffer<m::Check>>,
}

/// Proxy a single type of request to an authorizer.
struct AuthorizerProxy {
    authorize: Buffer<m::Authorize>,
    extract: Buffer<m::Extract>,
}

struct IssuerProxy {
    issue: Buffer<m::Issue>,
    recover_token: RefCell<Buffer<m::RecoverToken>>,
    recover_refresh: RefCell<Buffer<m::RecoverRefresh>>,
}

struct AuthorizationFuture<W, S> where W: WebRequest {
    registrar: RegistrarProxy,
    authorizer: AuthorizerProxy,
    solicitor: S,
    request: W,
    // Is an option because we may need to take it out.
    response: Option<W::Response>,
}

struct AccessTokenFuture<W> where W: WebRequest {
    registrar: RegistrarProxy,
    authorizer: AuthorizerProxy,
    issuer: IssuerProxy,
    request: W,
    // Is an option because we may need to take it out.
    response: Option<W::Response>,
}

struct ResourceFuture<W, C> where W: WebRequest {
    issuer: IssuerProxy,
    request: W,
    scopes: C,
    response: Option<W::Response>,
}

impl<W: WebResponse> ResourceProtection<W> {
    /// Turn `self` into a standard error.
    pub fn into_result(self) -> Result<W, W::Error> {
        match self {
            ResourceProtection::Respond(w) => Ok(w),
            ResourceProtection::Error(err) => Err(err),
        }
    }
}

impl RegistrarProxy {
    pub fn new<R>(registrar: Addr<AsActor<R>>) -> Self 
        where R: Registrar + 'static
    {
        RegistrarProxy {
            bound: RefCell::new(Buffer::new(registrar.clone().recipient())),
            negotiate: RefCell::new(Buffer::new(registrar.clone().recipient())),
            check: RefCell::new(Buffer::new(registrar.recipient())),
        }
    }

    pub fn is_waiting(&self) -> bool {
        self.bound.borrow().is_waiting()
        || self.negotiate.borrow().is_waiting()
        || self.check.borrow().is_waiting()
    }

    #[allow(dead_code)]
    pub fn error(&self) -> Option<MailboxError> {
        let berr = self.bound.borrow().error();
        let nerr = self.negotiate.borrow().error();
        let cerr = self.check.borrow().error();
        berr.or(nerr).or(cerr)
    }
    
    pub fn rearm(&mut self) {
        self.bound.borrow_mut().rearm();
        self.negotiate.borrow_mut().rearm();
        self.check.borrow_mut().rearm();
    }
}

impl Registrar for RegistrarProxy {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        if self.bound.borrow().unsent() {
            let bound = m::BoundRedirect {
                bound: ClientUrl {
                    client_id: Cow::Owned(bound.client_id.into_owned()),
                    redirect_uri: bound.redirect_uri.map(|uri| Cow::Owned(uri.into_owned())),
                }
            };
            self.bound.borrow_mut().send(bound);
        }

        match self.bound.borrow_mut().poll() {
            Ok(Async::NotReady) => Err(RegistrarError::PrimitiveError),
            Ok(Async::Ready(Ok(bound))) => Ok(BoundClient {
                client_id: match bound.client_id {
                    Cow::Borrowed(id) => Cow::Borrowed(id),
                    Cow::Owned(id) => Cow::Owned(id),
                },
                redirect_uri: bound.redirect_uri,
            }),
            Ok(Async::Ready(Err(err))) => Err(err),
            Err(()) => Err(RegistrarError::PrimitiveError),
        }
    }

    fn negotiate(&self, client: BoundClient, scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        if self.negotiate.borrow().unsent() {
            let negotiate = m::Negotiate {
                client: BoundClient {
                    client_id: Cow::Owned(client.client_id.into_owned()),
                    redirect_uri: Cow::Owned(client.redirect_uri.into_owned()),
                },
                scope,
            };
            self.negotiate.borrow_mut().send(negotiate);
        }

        match self.negotiate.borrow_mut().poll() {
            Ok(Async::NotReady) => Err(RegistrarError::PrimitiveError),
            Ok(Async::Ready(ready)) => ready,
            Err(()) => Err(RegistrarError::PrimitiveError),
        }
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        if self.check.borrow().unsent() {
            let check = m::Check {
                client: client_id.to_owned(),
                passphrase: passphrase.map(ToOwned::to_owned),
            };
            self.check.borrow_mut().send(check);
        }

        match self.check.borrow_mut().poll() {
            Ok(Async::NotReady) => Err(RegistrarError::PrimitiveError),
            Ok(Async::Ready(ready)) => ready,
            Err(()) => Err(RegistrarError::PrimitiveError),
        }
    }
}

impl AuthorizerProxy {
    pub fn new<A>(authorizer: Addr<AsActor<A>>) -> Self 
        where A: Authorizer + 'static
    {
        AuthorizerProxy {
            authorize: (Buffer::new(authorizer.clone().recipient())),
            extract: (Buffer::new(authorizer.recipient())),
        }
    }

    pub fn is_waiting(&self) -> bool {
        self.authorize.is_waiting()
        || self.extract.is_waiting()
    }

    #[allow(dead_code)]
    pub fn error(&self) -> Option<MailboxError> {
        let aerr = self.authorize.error();
        let eerr = self.extract.error();
        aerr.or(eerr)
    }
    
    pub fn rearm(&mut self) {
        self.authorize.rearm();
        self.extract.rearm();
    }
}

impl Authorizer for AuthorizerProxy {
    fn authorize(&mut self, grant: Grant) -> Result<String, ()> {
        if self.authorize.unsent() {
            self.authorize.send(m::Authorize {
                grant,
            });
        }

        match self.authorize.poll() {
            Ok(Async::NotReady) => Err(()),
            Ok(Async::Ready(ready)) => ready,
            Err(()) => Err(()),
        }
    }

    fn extract(&mut self, token: &str) -> Result<Option<Grant>, ()> {
        if self.extract.unsent() {
            self.extract.send(m::Extract {
                token: token.to_owned(),
            });
        }

        match self.extract.poll() {
            Ok(Async::NotReady) => Err(()),
            Ok(Async::Ready(ready)) => ready,
            Err(()) => Err(()),
        }
    }
}

impl IssuerProxy {
    pub fn new<I>(issuer: Addr<AsActor<I>>) -> Self 
        where I: Issuer + 'static
    {
        IssuerProxy {
            issue: Buffer::new(issuer.clone().recipient()),
            recover_token: RefCell::new(Buffer::new(issuer.clone().recipient())),
            recover_refresh: RefCell::new(Buffer::new(issuer.recipient())),
        }
    }

    pub fn is_waiting(&self) -> bool {
        self.issue.is_waiting()
        || self.recover_token.borrow().is_waiting()
        || self.recover_refresh.borrow().is_waiting()
    }

    #[allow(dead_code)]
    pub fn error(&self) -> Option<MailboxError> {
        let ierr = self.issue.error();
        let terr = self.recover_token.borrow().error();
        let rerr = self.recover_refresh.borrow().error();
        ierr.or(terr).or(rerr)
    }
    
    pub fn rearm(&mut self) {
        self.issue.rearm();
        self.recover_token.borrow_mut().rearm();
        self.recover_refresh.borrow_mut().rearm();
    }
}

impl Issuer for IssuerProxy {
    fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        if self.issue.unsent() {
            let issue = m::Issue {
                grant,
            };

            self.issue.send(issue);
        }

        match self.issue.poll() {
            Ok(Async::NotReady) => Err(()),
            Ok(Async::Ready(Ok(token))) => Ok(token),
            Ok(Async::Ready(Err(()))) => Err(()),
            Err(()) => Err(()),
        }
    }

    fn recover_token<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        if self.recover_token.borrow().unsent() {
            let recover = m::RecoverToken {
                token: token.to_string(),
            };

            self.recover_token.borrow_mut().send(recover);
        }

        match self.recover_token.borrow_mut().poll() {
            Ok(Async::NotReady) => Err(()),
            Ok(Async::Ready(ready)) => ready,
            Err(()) => Err(()),
        }
    }

    fn recover_refresh<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        if self.recover_refresh.borrow().unsent() {
            let recover = m::RecoverRefresh {
                token: token.to_string(),
            };

            self.recover_refresh.borrow_mut().send(recover);
        }

        match self.recover_refresh.borrow_mut().poll() {
            Ok(Async::NotReady) => Err(()),
            Ok(Async::Ready(ready)) => ready,
            Err(()) => Err(()),
        }
    }
}

struct RefMutPrimitive<'a, S: 'a>(&'a mut S);

impl<'a, W, S: 'a> OwnerSolicitor<&'a mut W> for RefMutPrimitive<'a, S> 
where
    W: WebRequest,
    S: OwnerSolicitor<W>,
{
    fn check_consent(&mut self, request: &mut &'a mut W, pre: &PreGrant) -> OwnerConsent<W::Response> {
        self.0.check_consent(*request, pre)
    }
}

impl<'a, W, C: 'a> Scopes<&'a mut W> for RefMutPrimitive<'a, C>
where
    W: WebRequest,
    C: Scopes<W>,
{
    fn scopes(&mut self, request: &mut &'a mut W) -> &[Scope] {
        self.0.scopes(*request)
    }
}

impl<W: WebRequest, S> Future for AuthorizationFuture<W, S> 
where 
    S: OwnerSolicitor<W>,
    W::Error: From<OAuthError>,
{
    type Item = W::Response;
    type Error = W::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let response_mut = &mut self.response;
        let result = {
            let endpoint = Generic {
                registrar: &self.registrar,
                authorizer: &mut self.authorizer,
                issuer: Vacant,
                solicitor: RefMutPrimitive(&mut self.solicitor),
                scopes: Vacant,
                response: || { response_mut.take().unwrap() },
            };

            let mut flow = match AuthorizationFlow::prepare(endpoint) {
                Ok(flow) => flow,
                Err(_) => unreachable!("Preconditions always fulfilled"),
            };

            flow.execute(&mut self.request)
        };

        // Weed out the terminating results.
        let oerr = match result {
            Ok(response) => return Ok(Async::Ready(response)),
            Err(SimpleError::Web(err)) => return Err(err),
            Err(SimpleError::OAuth(oauth)) => oauth,
        };

        // Could it have been the registrar or authorizer that failed?
        match oerr {
            OAuthError::PrimitiveError => (),
            other => return Err(other.into()),
        }

        // Are we getting this primitive error due to a pending reply?
        if !self.registrar.is_waiting() && !self.authorizer.is_waiting() {
            // No, this was fatal
            return Err(OAuthError::PrimitiveError.into());
        }

        self.registrar.rearm();
        self.authorizer.rearm();
        Ok(Async::NotReady)
    }
}

impl<W: WebRequest> Future for AccessTokenFuture<W> 
where
    W::Error: From<OAuthError>
{
    type Item = W::Response;
    type Error = W::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let response_mut = &mut self.response;
        let result = {
            let endpoint = Generic {
                registrar: &self.registrar,
                authorizer: &mut self.authorizer,
                issuer: &mut self.issuer,
                solicitor: Vacant,
                scopes: Vacant,
                response: || { response_mut.take().unwrap() },
            };

            let mut flow = match AccessTokenFlow::prepare(endpoint) {
                Ok(flow) => flow,
                Err(_) => unreachable!("Preconditions always fulfilled"),
            };

            flow.execute(&mut self.request)
        };

        // Weed out the terminating results.
        let oerr = match result {
            Ok(response) => return Ok(Async::Ready(response)),
            Err(SimpleError::Web(err)) => return Err(err),
            Err(SimpleError::OAuth(oauth)) => oauth,
        };

        // Could it have been the registrar or authorizer that failed?
        match oerr {
            OAuthError::PrimitiveError => (),
            other => return Err(other.into()),
        }

        // Are we getting this primitive error due to a pending reply?
        if !self.registrar.is_waiting() && !self.authorizer.is_waiting() && !self.issuer.is_waiting() {
            // No, this was fatal
            return Err(OAuthError::PrimitiveError.into());
        }

        self.registrar.rearm();
        self.authorizer.rearm();
        self.issuer.rearm();
        Ok(Async::NotReady)
    }
}

impl<W: WebRequest, C> Future for ResourceFuture<W, C> 
where 
    C: Scopes<W>,
    W::Error: From<OAuthError>,
{
    type Item = Grant;
    type Error = ResourceProtection<W::Response>;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let response_mut = &mut self.response;
        let result = {
            let endpoint = Generic {
                registrar: Vacant,
                authorizer: Vacant,
                issuer: &mut self.issuer,
                solicitor: Vacant,
                scopes: RefMutPrimitive(&mut self.scopes),
                response: || { response_mut.take().unwrap() },
            };

            let mut flow = match ResourceFlow::prepare(endpoint) {
                Ok(flow) => flow,
                Err(_) => unreachable!("Preconditions always fulfilled"),
            };

            flow.execute(&mut self.request)
        };

        // Weed out the terminating results.
        let err = match result {
            Ok(grant) => return Ok(Async::Ready(grant)),
            Err(err) => err,
        };

        // Err may be a response
        let err = match err {
            Ok(response) => return Err(ResourceProtection::Respond(response)),
            Err(err) => err,
        };

        // Now we are at the errors produced by the endpoint.
        // Since we control the endpoint, second representations is `OAuthError`.
        match err {
            SimpleError::OAuth(OAuthError::PrimitiveError) => (),
            SimpleError::OAuth(err) => return Err(ResourceProtection::Error(err.into())),
            SimpleError::Web(err) => return Err(ResourceProtection::Error(err)),
        }

        // Are we getting this primitive error due to a pending reply?
        if !self.issuer.is_waiting() {
            // No, this was fatal
            return Err(ResourceProtection::Error(OAuthError::PrimitiveError.into()));
        }

        self.issuer.rearm();
        Ok(Async::NotReady)
    }
}

impl<M> Buffer<M> 
where 
    M: Message + Send + 'static,
    M::Result: Send + Clone + 'static,
{
    pub fn new(recipient: Recipient<M>) -> Self {
        Buffer {
            recipient,
            state: BufferState::NotSent,
        }
    }

    /// Test if this was the cause for an temporary error.
    pub fn is_waiting(&self) -> bool {
        self.state.is_waiting()
    }

    pub fn error(&self) -> Option<MailboxError> {
        self.state.error()
    }

    pub fn rearm(&mut self) {
        self.state.rearm();
    }

    pub fn unsent(&self) -> bool {
        match self.state {
            BufferState::NotSent => true,
            _ => false,
        }
    }

    pub fn send(&mut self, msg: M) {
        match self.state {
            BufferState::NotSent => (),
            // Only send message once
            _ => panic!("Buffer should not send twice"),
        }

        let request = self.recipient.send(msg);
        self.state = BufferState::NotYet(request);
    }

    pub fn poll(&mut self) -> Poll<M::Result, ()> {
        self.state.poll()
    }
}

impl<M> BufferState<M> 
where 
    M: Message + Send + 'static,
    M::Result: Send + Clone + 'static,
{
    pub fn is_waiting(&self) -> bool {
        match self {
            BufferState::NotYet(_) => true,
            _ => false,
        }
    }

    pub fn error(&self) -> Option<MailboxError> {
        match self {
            BufferState::Error(MailboxError::Closed) => Some(MailboxError::Closed),
            BufferState::Error(MailboxError::Timeout) => Some(MailboxError::Timeout),
            BufferState::Poison => panic!("Found poisoned buffer"),
            _ => None,
        }
    }

    pub fn poll(&mut self) -> Poll<M::Result, ()> {
        use std::mem::replace;

        let state = replace(self, BufferState::Poison);

        let r = match state {
            BufferState::NotSent => panic!("Buffer polled before send"),
            BufferState::NotYet(mut inner) => match inner.poll() {
                Ok(Async::Ready(result)) => result,
                Ok(Async::NotReady) => {
                    replace(self, BufferState::NotYet(inner));
                    return Ok(Async::NotReady)
                },
                Err(mb) => {
                    replace(self, BufferState::Error(mb));
                    return Err(())
                },
            },
            BufferState::Received(r) => r,
            BufferState::Consumed(_) => panic!("Buffer not reamred after consume"),
            BufferState::Error(_) => panic!("Buffer polled after error"),
            BufferState::Poison => panic!("Found poisoned buffer"),
        };

        // Put back copy
        replace(self, BufferState::Consumed(r.clone()));
        Ok(Async::Ready(r))
    }

    pub fn rearm(&mut self) {
        use std::mem::replace;

        let state = replace(self, BufferState::Poison);
        let next = match state {
            BufferState::Consumed(r) => BufferState::Received(r),
            other => other,
        };
        replace(self, next);
    }
}
