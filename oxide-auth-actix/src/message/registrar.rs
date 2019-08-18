use primitives::registrar::{BoundClient, ClientUrl, Registrar, RegistrarError, PreGrant};
use primitives::scope::Scope;

use super::super::actix::{Handler, Message};
use super::super::AsActor;

/// Request a bound redirect.
#[derive(Clone, Debug)]
pub struct BoundRedirect {
    /// The parameters provided in the authorization code request.
    pub bound: ClientUrl<'static>,
}

impl Message for BoundRedirect {
    type Result = Result<BoundClient<'static>, RegistrarError>;
}

/// Negotiate the scope of the to-be-issued grant.
#[derive(Clone, Debug)]
pub struct Negotiate {
    /// The client (and redirect uri) requesting the grant.
    pub client: BoundClient<'static>,
    
    /// Scope if one has been requested.
    pub scope: Option<Scope>
}

impl Message for Negotiate {
    type Result = Result<PreGrant, RegistrarError>;
}

/// Ask a registrar to check the provided client authorization.
#[derive(Clone, Debug)]
pub struct Check {
    /// The client according to the `Authorization` header.
    pub client: String,

    /// The passphrase according to the `Authorization` header, if one was provided.
    pub passphrase: Option<Vec<u8>>,
}

impl Message for Check {
    type Result = Result<(), RegistrarError>;
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
    type Result = Result<(), RegistrarError>;

    fn handle(&mut self, msg: Check, _: &mut Self::Context) -> Self::Result {
        self.0.check(&msg.client, msg.passphrase.as_ref().map(Vec::as_slice))
    }
}
