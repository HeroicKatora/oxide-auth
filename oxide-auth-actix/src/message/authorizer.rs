use actix::{Handler, Message};
use oxide_auth_core::primitives::authorizer::Authorizer;
use oxide_auth_core::primitives::grant::Grant;

use crate::AsActor;

/// Command authorization of a grant.
pub struct Authorize {
    /// The grant to generate an authorization code for.
    pub grant: Grant,
}
impl Message for Authorize {
    type Result = Result<String, ()>;
}

/// Use up an authorization code.
pub struct Extract {
    /// The previously generated token.
    ///
    /// Each token should only be usable once.
    pub token: String,
}

impl Message for Extract {
    type Result = Result<Option<Grant>, ()>;
}

impl<A: Authorizer + 'static> Handler<Authorize> for AsActor<A> {
    type Result = Result<String, ()>;

    fn handle(&mut self, msg: Authorize, _: &mut Self::Context) -> Self::Result {
        self.0.authorize(msg.grant)
    }
}

impl<A: Authorizer + 'static> Handler<Extract> for AsActor<A> {
    type Result = Result<Option<Grant>, ()>;

    fn handle(&mut self, msg: Extract, _: &mut Self::Context) -> Self::Result {
        self.0.extract(&msg.token)
    }
}
