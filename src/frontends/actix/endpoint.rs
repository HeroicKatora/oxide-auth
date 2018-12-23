//! Provides a configurable actor with the functionality of a code grant frontend.
use code_grant::endpoint::{AuthorizationFlow, AccessTokenFlow, ResourceFlow};
use code_grant::endpoint::{OwnerSolicitor, OwnerConsent, PreGrant};

use super::actix::{Actor, Context, Handler, MessageResult};
use super::message::{AccessToken, AuthorizationCode, BoxedOwner, Guard};
use super::resolve::{ResolvedRequest, ResolvedResponse};

/// A tag type to signal that no handler for this request type has been configured on the endpoint.
pub struct NoHandler;

struct OwnerBoxHandler(BoxedOwner<ResolvedRequest>);

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
pub struct CodeGrantEndpoint<State, Auth=NoHandler, Grant=NoHandler, Access=NoHandler> {
    state: State,
    authorization: Auth,
    grant: Grant,
    access: Access,
}

impl<State> CodeGrantEndpoint<State, NoHandler, NoHandler, NoHandler> {
    /// Create a new endpoint with some state.
    ///
    /// Call `with_authorization`, `with_grant` and `with_guard` before starting the actor to
    /// configure the actor for handling of the respective requests.
    pub fn new(state: State) -> Self {
        CodeGrantEndpoint {
            state,
            authorization: NoHandler,
            grant: NoHandler,
            access: NoHandler,
        }
    }
}

impl<S, A, B, C> CodeGrantEndpoint<S, A, B, C> {
    /// Configure the authorization handler for the endpoint.
    ///
    /// The provided method or closure must construct an authorization flow based on the
    /// actor's state.  The constructed flow will be used to handle incoming messages.
    pub fn with_authorization<F>(self, f: F) -> CodeGrantEndpoint<S, F, B, C>
        where F: for<'a> Fn(&'a mut S) -> AuthorizationFlow<'a>
    {
        CodeGrantEndpoint {
            state: self.state,
            authorization: f,
            grant: self.grant,
            access: self.access,
        }
    }

    /// Configure the code grant request handler for the endpoint.
    ///
    /// The provided method or closure must construct a code grant flow based on the
    /// actor's state.  The constructed flow will be used to handle incoming messages.
    pub fn with_grant<F>(self, f: F) -> CodeGrantEndpoint<S, A, F, C>
        where F: for<'a> Fn(&'a mut S) -> GrantFlow<'a>
    {
        CodeGrantEndpoint {
            state: self.state,
            authorization: self.authorization,
            grant: f,
            access: self.access,
        }
    }

    /// Configure the guard request handler for the endpoint.
    ///
    /// The provided method or closure must construct a guard flow based on the
    /// actor's state.  The constructed flow will be used to handle incoming messages.
    pub fn with_guard<F>(self, f: F) -> CodeGrantEndpoint<S, A, B, F>
        where F: for<'a> Fn(&'a mut S) -> AccessFlow<'a>
    {
        CodeGrantEndpoint {
            state: self.state,
            authorization: self.authorization,
            grant: self.grant,
            access: f,
        }
    }
}

impl<State, A, B, C> Actor for CodeGrantEndpoint<State, A, B, C>
    where State: 'static, A: 'static, B: 'static, C: 'static
{
    type Context = Context<Self>;
}

impl<State, A, B, C> Handler<AuthorizationCode> for CodeGrantEndpoint<State, A, B, C>
where
    State: 'static, A: 'static, B: 'static, C: 'static,
    A: for<'a> Fn(&'a mut State) -> AuthorizationFlow<'a>
{
    type Result = MessageResult<AuthorizationCode>;

    fn handle(&mut self, msg: AuthorizationCode, _: &mut Self::Context) -> Self::Result {
        let flow = (self.authorization)(&mut self.state);
        let pending = flow.handle(msg.request);
        let result = pending.complete(OwnerBoxHandler(msg.owner));
        MessageResult(result)
    }
}

impl<State, A, B, C> Handler<AccessToken> for CodeGrantEndpoint<State, A, B, C>
where
    State: 'static, A: 'static, B: 'static, C: 'static,
    B: for<'a> Fn(&'a mut State) -> GrantFlow<'a>
{
    type Result = MessageResult<AccessToken>;

    fn handle(&mut self, msg: AccessToken, _: &mut Self::Context) -> Self::Result {
        let flow = (self.grant)(&mut self.state);
        MessageResult(flow.handle(msg.0))
    }
}

impl<State, A, B, C> Handler<Guard> for CodeGrantEndpoint<State, A, B, C>
where
    State: 'static, A: 'static, B: 'static, C: 'static,
    C: for<'a> Fn(&'a mut State) -> AccessFlow<'a>
{
    type Result = MessageResult<Guard>;

    fn handle(&mut self, msg: Guard, _: &mut Self::Context) -> Self::Result {
        let flow = (self.access)(&mut self.state);
        MessageResult(flow.handle(msg.0))
    }
}

impl OwnerAuthorizer<ResolvedRequest> for OwnerBoxHandler {
    fn check_authorization(self, _: ResolvedRequest, pre_grant: &PreGrant)
        -> OwnerAuthorization<ResolvedResponse>
    {
        (self.0)(pre_grant)
    }
}
