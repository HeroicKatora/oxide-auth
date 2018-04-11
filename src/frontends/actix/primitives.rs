//! Actors of primitives and glue code
use super::defer::DeferableComputation;
use super::actix::dev::*;

use super::futures::Future;

use primitives::prelude::*;
use primitives::grant::Grant;

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
