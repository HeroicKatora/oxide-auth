use primitives::registrar::{BoundClient, ClientUrl, Registrar, RegistrarError, PreGrant};
use primitives::scope::Scope;

use super::super::actix::{Handler, Message};
use super::super::AsActor;

use ring::error::Unspecified;

/// Request a bound redirect.
pub struct BoundRedirect {
    pub bound: ClientUrl<'static>,
}

impl Message for BoundRedirect {
    type Result = Result<BoundClient<'static>, RegistrarError>;
}

pub struct Negotiate {
    pub client: BoundClient<'static>,
    pub scope: Option<Scope>
}

impl Message for Negotiate {
    type Result = Result<PreGrant, RegistrarError>;
}

pub struct Check {
    pub client: String,
    pub passphrase: Option<Vec<u8>>,
}

impl Message for Check {
    type Result = Result<(), Unspecified>;
}

impl<R: Registrar + 'static> Handler<BoundRedirect> for AsActor<R> {
    type Result = Result<BoundClient<'static>, RegistrarError>;

    fn handle(&mut self, msg: BoundRedirect, _: &mut Self::Context) -> Self::Result {
        self.0.bound_redirect(msg.bound)
    }
}

impl<R: Registrar + 'static> Handler<Negotiate> for AsActor<R> {
    type Result = Result<PreGrant, RegistrarError>;

    fn handle(&mut self, msg: Negotiate, _: &mut Self::Context) -> Self::Result {
        self.0.negotiate(msg.client, msg.scope)
    }
}

impl<R: Registrar + 'static> Handler<Check> for AsActor<R> {
    type Result = Result<(), Unspecified>;

    fn handle(&mut self, msg: Check, _: &mut Self::Context) -> Self::Result {
        self.0.check(&msg.client, msg.passphrase.as_ref().map(Vec::as_slice))
    }
}
