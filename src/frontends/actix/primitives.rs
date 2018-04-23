//! Actors of primitives and glue code
use std::borrow::Cow;

use super::defer::DeferableComputation;
use super::actix::dev::*;

use super::futures::Future;
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

pub struct BindRedirect {
    pub client: String,

    pub redirect_uri: Option<Url>,
}

impl BindRedirect {
    pub fn client_url(&self) -> ClientUrl {
        ClientUrl {
            client_id: Cow::Borrowed(&self.client),
            redirect_uri: self.redirect_uri.as_ref().map(Cow::Borrowed),
        }
    }
}

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

impl Message for BindRedirect {
    type Result = Result<BoundClient, RegistrarError>;
}

impl<R: Registrar + 'static> Handler<BindRedirect> for RegistrarActor<R> {
    type Result = MessageResult<BindRedirect>;

    fn handle(&mut self, msg: BindRedirect, _: &mut Self::Context) -> Self::Result {
        match self.0.bound_redirect(msg.client_url()) {
            Err(err) => MessageResult(Err(err)),
            Ok(bound) => MessageResult(Ok(bound.into())),
        }
    }
}

pub struct DeferredAuthorizer<A: Authorizer + 'static> {
    connection: Addr<Unsync, AuthorizeActor<A>>,
    cached_result: DeferableComputation<Request<Unsync, AuthorizeActor<A>, AuthorizationRequest>>,
}

impl<A: Authorizer + 'static> DeferredAuthorizer<A> {
    fn authorize(&mut self, grant: Grant) -> Result<String, ()> {
        let connection = self.connection.clone();
        let retrieve = move || connection.send(AuthorizationRequest(grant));
        self.cached_result.initialize(retrieve);
        match self.cached_result.make_answer() {
            Some(Ok(token)) => Ok(token),
            _ => Err(())
        }
    }
}
