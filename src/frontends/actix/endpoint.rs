//! Provides a configurable actor with the functionality of a code grant frontend.
use code_grant::endpoint::{AuthorizationFlow, AccessTokenFlow, ResourceFlow};
use code_grant::endpoint::{Endpoint, OwnerSolicitor, OwnerConsent, PreGrant, WebRequest};

use super::actix::dev::MessageResponse;
use super::actix::{Actor, Context, Handler, Message, MessageResult};
use super::message::{AccessToken, AuthorizationCode, BoxedOwner, Resource};
use super::AsActor;

/// A tag type to signal that no handler for this request type has been configured on the endpoint.
pub struct NoHandler;

impl<P: 'static> Actor for AsActor<P> {
    type Context = Context<Self>;
}

impl<W, P: 'static, E: 'static> Handler<AuthorizationCode<W>> for AsActor<P> 
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
            .execute(msg.request)
            .finish()
    }
}

/*
/// An actor handling OAuth2 code grant requests.
///
/// Centrally manages all incoming requests, authorization codes, tokens as well as guarding of
/// resources.  The specific endpoints need to be derived from the state.
///
/// The object doubles as a builder allowing customization of each flow individually before the
/// actor is started. Typical code looks something like this:
///
/// ```no_run
/// # extern crate actix;
/// # extern crate oxide_auth;
/// # use actix::{Actor, Addr};
/// # use oxide_auth::frontends::actix::*;
/// # use oxide_auth::primitives::prelude::*;
/// # fn main() {
/// # let (registrar, authorizer, issuer, scope)
/// #     : (ClientMap, Storage<RandomGenerator>, TokenSigner, &'static[Scope])
/// #     = unimplemented!();
/// let handle: Addr<_> = CodeGrantEndpoint::new(
///         (registrar, authorizer, issuer, scope)
///     )
///     .with_authorization(|state| AuthorizationFlow::new(&state.0, &mut state.1))
///     .with_grant(|state| GrantFlow::new(&state.0, &mut state.1, &mut state.2))
///     .with_guard(|state| AccessFlow::new(&mut state.2, state.3))
///     .start();
/// # }
/// ```

impl OwnerAuthorizer<ResolvedRequest> for OwnerBoxHandler {
    fn check_authorization(self, _: ResolvedRequest, pre_grant: &PreGrant)
        -> OwnerAuthorization<ResolvedResponse>
    {
        (self.0)(pre_grant)
    }
}
*/
