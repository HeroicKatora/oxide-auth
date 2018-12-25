//! Provides a configurable actor with the functionality of a code grant frontend.
use code_grant::endpoint::{AuthorizationFlow, AccessTokenFlow, ResourceFlow};
use code_grant::endpoint::{Endpoint, WebRequest};

use super::actix::{Actor, Context, Handler};
use super::message::{AccessToken, AuthorizationCode, Resource};
use super::{AsActor, ResourceProtection};

// /// A tag type to signal that no handler for this request type has been configured on the endpoint.
// pub struct NoHandler;

impl<P: 'static> Actor for AsActor<P> {
    type Context = Context<Self>;
}

impl<W, P, E> Handler<AuthorizationCode<W>> for AsActor<P> 
where 
    W: WebRequest<Error=E> + Send + Sync + 'static,
    P: Endpoint<W, Error=E> + 'static,
    W::Response: Send + Sync + 'static,
    E: Send + Sync + 'static,
{
    type Result = Result<W::Response, W::Error>;

    fn handle(&mut self, msg: AuthorizationCode<W>, _: &mut Self::Context) -> Self::Result {
        AuthorizationFlow::prepare(&mut self.0)?.execute(msg.0)
    }
}

impl<W, P, E> Handler<AccessToken<W>> for AsActor<P> 
where 
    W: WebRequest<Error=E> + Send + Sync + 'static,
    P: Endpoint<W, Error=E> + 'static,
    W::Response: Send + Sync + 'static,
    E: Send + Sync + 'static,
{
    type Result = Result<W::Response, W::Error>;

    fn handle(&mut self, msg: AccessToken<W>, _: &mut Self::Context) -> Self::Result {
        AccessTokenFlow::prepare(&mut self.0)?.execute(msg.0)
    }
}

impl<W, P, E> Handler<Resource<W>> for AsActor<P> 
where 
    W: WebRequest<Error=E> + Send + Sync + 'static,
    P: Endpoint<W, Error=E> + 'static,
    W::Response: Send + Sync + 'static,
    E: Send + Sync + 'static,
{
    type Result = Result<(), ResourceProtection<W::Response>>;

    fn handle(&mut self, msg: Resource<W>, _: &mut Self::Context) -> Self::Result {
        let result = ResourceFlow::prepare(&mut self.0)
            .map_err(ResourceProtection::Error)?
            .execute(msg.0);

        match result {
            Ok(()) => Ok(()),
            Err(Ok(response)) => Err(ResourceProtection::Respond(response)),
            Err(Err(error)) => Err(ResourceProtection::Error(error)),
        }
    }
}
