use primitives::issuer::{Issuer, IssuedToken};
use primitives::grant::Grant;

use super::super::actix::{Handler, Message};
use super::super::AsActor;

pub struct Issue {
    pub grant: Grant,
}

impl Message for Issue {
    type Result = Result<IssuedToken, ()>;
}

pub struct RecoverToken {
    pub token: String,
}

impl Message for RecoverToken {
    type Result = Option<Grant>;
}

pub struct RecoverRefresh {
    pub token: String,
}

impl Message for RecoverRefresh {
    type Result = Option<Grant>;
}

impl<I: Issuer + 'static> Handler<Issue> for AsActor<I> {
    type Result = Result<IssuedToken, ()>;

    fn handle(&mut self, msg: Issue, _: &mut Self::Context) -> Self::Result {
        self.0.issue(msg.grant)
    }
}


impl<I: Issuer + 'static> Handler<RecoverToken> for AsActor<I> {
    type Result = Option<Grant>; 

    fn handle(&mut self, msg: RecoverToken, _: &mut Self::Context) -> Self::Result {
        self.0.recover_token(&msg.token)
    }
}

impl<I: Issuer + 'static> Handler<RecoverRefresh> for AsActor<I> {
    type Result = Option<Grant>;

    fn handle(&mut self, msg: RecoverRefresh, _: &mut Self::Context) -> Self::Result {
        self.0.recover_refresh(&msg.token)
    }
}
