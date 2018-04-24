//! Actors of primitives and glue code
use std::borrow::Cow;

use super::defer::DeferableComputation;
use super::actix::dev::*;

use super::futures::{Async, Future, Poll};
use url::Url;

use primitives::grant::Grant;
use primitives::prelude::*;
use primitives::registrar::{self, ClientUrl, EncodedClient, RegistrarError};

pub struct AuthorizeActor<A: Authorizer>(A);

impl<A: Authorizer + 'static> Actor for AuthorizeActor<A> {
    type Context = Context<Self>;
}


pub struct AuthorizationRequest(pub Grant);

impl Message for AuthorizationRequest {
    type Result = Result<String, ()>;
}

impl<A: Authorizer + 'static> Handler<AuthorizationRequest> for AuthorizeActor<A> {
    type Result = Result<String, ()>;

    fn handle(&mut self, msg: AuthorizationRequest, _: &mut Self::Context) -> Self::Result {
        self.0.authorize(msg.0)
    }
}


pub struct ExtractAuthorization(pub String);

impl Message for ExtractAuthorization {
    type Result = Option<Grant>;
}

impl<A: Authorizer + 'static> Handler<ExtractAuthorization> for AuthorizeActor<A> {
    type Result = MessageResult<ExtractAuthorization>;

    fn handle(&mut self, msg: ExtractAuthorization, _: &mut Self::Context) -> Self::Result {
        MessageResult(self.0.extract(&msg.0))
    }
}



pub struct RegistrarActor<R: Registrar>(R);

impl<R: Registrar + 'static> Actor for RegistrarActor<R> {
    type Context = Context<Self>;
}

pub struct BindRequest {
    pub client: String,

    pub redirect_uri: Option<Url>,
}

impl BindRequest {
    pub fn client_url(&self) -> ClientUrl {
        ClientUrl {
            client_id: Cow::Borrowed(&self.client),
            redirect_uri: self.redirect_uri.as_ref().map(Cow::Borrowed),
        }
    }
}

#[derive(Clone)]
pub struct BoundClient {
    /// The identifier of the client, moved from the request.
    pub client_id: String,

    /// The chosen redirection endpoint url, moved from the request of overwritten.
    pub redirect_uri: Url,

    /// A reference to the client instance, for authentication and to retrieve additional
    /// information.
    pub client: EncodedClient,
}

impl<'a> From<registrar::BoundClient<'a>> for BoundClient {
    fn from(bound: registrar::BoundClient<'a>) -> Self {
        BoundClient {
            client_id: bound.client_id.into_owned(),
            redirect_uri: bound.redirect_uri.into_owned(),
            client: bound.client.clone(),
        }
    }
}

impl Message for BindRequest {
    type Result = Result<BoundClient, RegistrarError>;
}

impl<R: Registrar + 'static> Handler<BindRequest> for RegistrarActor<R> {
    type Result = MessageResult<BindRequest>;

    fn handle(&mut self, msg: BindRequest, _: &mut Self::Context) -> Self::Result {
        match self.0.bound_redirect(msg.client_url()) {
            Err(err) => MessageResult(Err(err)),
            Ok(bound) => MessageResult(Ok(bound.into())),
        }
    }
}

pub struct UnsyncAuthorizationEndpoint<A: Authorizer + 'static, R: Registrar + 'static> {
    authorizer_connection: Addr<Unsync, AuthorizeActor<A>>,
    registrar_connection: Addr<Unsync, RegistrarActor<R>>,
    deferred_bind: DeferableComputation<Request<Unsync, RegistrarActor<R>, BindRequest>>,
    deferred_auth: DeferableComputation<Request<Unsync, AuthorizeActor<A>, AuthorizationRequest>>,
}

impl<A, R> UnsyncAuthorizationEndpoint<A, R>
where
    A: Authorizer + 'static,
    R: Registrar + 'static,
{
    fn bind(&mut self, bound: BindRequest) -> Result<BoundClient, RegistrarError> {
        let connection = self.registrar_connection.clone();
        let retrieve = move || connection.send(bound);
        self.deferred_bind.initialize(retrieve);
        self.deferred_bind.make_answer().unwrap_or(Err(RegistrarError::Unregistered))
    }

    fn authorize(&mut self, grant: AuthorizationRequest) -> Result<String, ()> {
        let connection = self.authorizer_connection.clone();
        let retrieve = move || connection.send(grant);
        self.deferred_auth.initialize(retrieve);
        match self.deferred_auth.make_answer() {
            Some(Ok(token)) => Ok(token),
            _ => Err(())
        }
    }
}

impl<A, R> Future for UnsyncAuthorizationEndpoint<A, R>
where
    A: Authorizer + 'static,
    R: Registrar + 'static,
{
    type Item = ();
    type Error = MailboxError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.deferred_bind.started().map(|mut started| started.poll()) {
            Some(Ok(Async::NotReady)) => return Ok(Async::NotReady),
            Some(Err(err)) => return Err(err),
            Some(Ok(Async::Ready(()))) => (),
            None => (),
        }

        match self.deferred_auth.started().map(|mut started| started.poll()) {
            Some(Ok(Async::NotReady)) => return Ok(Async::NotReady),
            Some(Err(err)) => return Err(err),
            Some(Ok(Async::Ready(()))) => (),
            None => (),
        }

        Ok(Async::Ready(()))
    }
}
