//! Provides a configurable actor with the functionality of a code grant frontend.
use code_grant::endpoint::{AuthorizationFlow, AccessTokenFlow, ResourceFlow};
use code_grant::endpoint::{Endpoint, WebRequest};

use super::actix::{Actor, Context, Handler, Message};
use super::message::{AccessToken, AuthorizationCode, Resource};
use super::AsActor;

/// A tag type to signal that no handler for this request type has been configured on the endpoint.
pub struct NoHandler;

impl<P: 'static> Actor for AsActor<P> {
    type Context = Context<Self>;
}

impl<W, P, E> Handler<AuthorizationCode<W>> for AsActor<P> 
where 
    W: WebRequest<Error=E>,
    P: Endpoint<W, Error=E> + 'static,
    W::Response: Send + Sync + 'static,
    E: Send + Sync + 'static,
    AuthorizationCode<W>: Message<Result=Result<W::Response, E>>,
{
    type Result = Result<W::Response, W::Error>;

    fn handle(&mut self, msg: AuthorizationCode<W>, _: &mut Self::Context) -> Self::Result {
        AuthorizationFlow::prepare(&mut self.0)?
            .execute(msg.0)
            .finish()
    }
}

impl<W, P, E> Handler<AccessToken<W>> for AsActor<P> 
where 
    W: WebRequest<Error=E>,
    P: Endpoint<W, Error=E> + 'static,
    W::Response: Send + Sync + 'static,
    E: Send + Sync + 'static,
    AccessToken<W>: Message<Result=Result<W::Response, E>>,
{
    type Result = Result<W::Response, W::Error>;

    fn handle(&mut self, msg: AccessToken<W>, _: &mut Self::Context) -> Self::Result {
        AccessTokenFlow::prepare(&mut self.0)?
            .execute(msg.0)
    }
}

impl<W, P, E> Handler<Resource<W>> for AsActor<P> 
where 
    W: WebRequest<Error=E>,
    P: Endpoint<W, Error=E> + 'static,
    W::Response: Send + Sync + 'static,
    E: Send + Sync + 'static,
    Resource<W>: Message<Result=Result<(), Result<W::Response, E>>>,
{
    type Result = Result<(), Result<W::Response, W::Error>>;

    fn handle(&mut self, msg: Resource<W>, _: &mut Self::Context) -> Self::Result {
        ResourceFlow::prepare(&mut self.0).map_err(Err)?
            .execute(msg.0)
    }
}
