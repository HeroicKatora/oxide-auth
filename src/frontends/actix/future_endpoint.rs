use std::borrow::Cow;
use std::cell::RefCell;

use primitives::authorizer::Authorizer;
// use primitives::issuer::Issuer;
use primitives::registrar::{BoundClient, ClientUrl, Registrar, RegistrarError, PreGrant};
use primitives::scope::Scope;
use primitives::grant::Grant;
use code_grant::endpoint::{AuthorizationFlow, OwnerSolicitor, OwnerConsent, OAuthError, WebRequest};
use frontends::simple::endpoint::{Error as SimpleError, Generic, Vacant};

use super::message as m;

use super::actix::{Addr, MailboxError, Message, Recipient};
use super::actix::dev::RecipientRequest;
use super::futures::{Async, Future, Poll};
use super::AsActor;

pub fn authorization<R, A, S, W>(
    registrar: Addr<AsActor<R>>,
    authorizer: Addr<AsActor<A>>,
    solicitor: S,
    request: W,
    response: W::Response
)
    -> Box<Future<Item=Result<W::Response, W::Error>, Error=MailboxError> + 'static>
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

struct AuthorizationFuture<W, S> where W: WebRequest {
    registrar: RegistrarProxy,
    authorizer: AuthorizerProxy,
    solicitor: S,
    request: W,
    // Is an option because we may need to take it out.
    response: Option<W::Response>,
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

    pub fn error(&self) -> Option<MailboxError> {
        self.bound.borrow().error()
            .or(self.negotiate.borrow().error())
            .or(self.check.borrow().error())
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
                scope: scope,
            };
            self.negotiate.borrow_mut().send(negotiate);
        }

        match self.negotiate.borrow_mut().poll() {
            Ok(Async::NotReady) => Err(RegistrarError::PrimitiveError),
            Ok(Async::Ready(Ok(grant))) => Ok(grant),
            Ok(Async::Ready(Err(err))) => Err(err),
            Err(()) => Err(RegistrarError::PrimitiveError),
        }
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        if self.check.borrow().unsent() {
            let check = m::Check {
                client: client_id.to_owned(),
                passphrase: passphrase.map(|p| p.to_owned()),
            };
            self.check.borrow_mut().send(check);
        }

        match self.check.borrow_mut().poll() {
            Ok(Async::NotReady) => Err(RegistrarError::PrimitiveError),
            Ok(Async::Ready(Ok(ready))) => Ok(ready),
            Ok(Async::Ready(Err(err))) => Err(err),
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

    pub fn error(&self) -> Option<MailboxError> {
        self.authorize.error()
            .or(self.extract.error())
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
            Ok(Async::Ready(Ok(token))) => Ok(token),
            Ok(Async::Ready(Err(()))) => Err(()),
            Err(()) => Err(()),
        }
    }

    fn extract(&mut self, token: &str) -> Option<Grant> {
        if self.extract.unsent() {
            self.extract.send(m::Extract {
                token: token.to_owned(),
            });
        }

        match self.extract.poll() {
            Ok(Async::NotReady) => None,
            Ok(Async::Ready(Some(grant))) => Some(grant),
            Ok(Async::Ready(None)) => None,
            Err(()) => None,
        }
    }
}

struct RefMutSolicitor<'a, S: 'a>(&'a mut S);

impl<'a, W, S: 'a> OwnerSolicitor<&'a mut W> for RefMutSolicitor<'a, S> 
where
    W: WebRequest,
    S: OwnerSolicitor<W>,
{
    fn check_consent(&mut self, request: &mut &'a mut W, pre: &PreGrant) -> OwnerConsent<W::Response> {
        self.0.check_consent(*request, pre)
    }
}

impl<W: WebRequest, S> Future for AuthorizationFuture<W, S> 
where 
    S: OwnerSolicitor<W>,
    W::Error: From<OAuthError>,
{
    type Item = Result<W::Response, W::Error>;
    type Error = MailboxError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {

        let response_mut = &mut self.response;
        let result = {
            let endpoint = Generic {
                registrar: &self.registrar,
                authorizer: &mut self.authorizer,
                issuer: Vacant,
                solicitor: RefMutSolicitor(&mut self.solicitor),
                scopes: Vacant,
                response: || { response_mut.take().unwrap() },
            };

            let mut flow = match AuthorizationFlow::prepare(endpoint) {
                Ok(flow) => flow,
                Err(_) => unreachable!("Preconditions always fulfilled"),
            };

            flow.execute(&mut self.request).finish()
        };

        // Weed out the terminating results.
        let oerr = match result {
            Ok(response) => return Ok(Async::Ready(Ok(response))),
            Err(SimpleError::Web(err)) => return Ok(Async::Ready(Err(err))),
            Err(SimpleError::OAuth(oauth)) => oauth,
        };

        // Could it have been the registrar or authorizer that failed?
        match oerr {
            OAuthError::PrimitiveError => (),
            other => return Ok(Async::Ready(Err(other.into()))),
        }

        // Are we getting this primitive error due to a pending reply?
        if !self.registrar.is_waiting() && !self.authorizer.is_waiting() {
            // Is this because of a terminal mailbox error?
            if let Some(mb) = self.registrar.error().or(self.authorizer.error()) {
                return Err(mb)
            }

            // It was some other primitive that failed.
            return Ok(Async::Ready(Err(OAuthError::PrimitiveError.into())));
        }

        self.registrar.rearm();
        self.authorizer.rearm();
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
