use primitives::authorizer::Authorizer;
use primitives::grant::Grant;

use super::super::actix::{Handler, Message};
use super::super::AsActor;

pub struct Authorize {
    pub grant: Grant,
}

impl Message for Authorize {
    type Result = Result<String, ()>;
}

pub struct Extract {
    pub token: String,
}

impl Message for Extract {
    type Result = Option<Grant>;
}

impl<A: Authorizer + 'static> Handler<Authorize> for AsActor<A> {
    type Result = Result<String, ()>;

    fn handle(&mut self, msg: Authorize, _: &mut Self::Context) -> Self::Result {
        self.0.authorize(msg.grant)
    }
}

impl<A: Authorizer + 'static> Handler<Extract> for AsActor<A> {
    type Result = Option<Grant>; 

    fn handle(&mut self, msg: Extract, _: &mut Self::Context) -> Self::Result {
        self.0.extract(&msg.token)
    }
}
