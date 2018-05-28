use std::marker::PhantomData;
use code_grant::frontend::{AuthorizationFlow, GrantFlow, AccessFlow};

use super::actix::{Actor, Context, Handler, MessageResult};
use super::message::{AccessToken, AuthorizationCode, Guard};

pub struct NoHandler;

pub struct CodeGrantEndpoint<State, Auth=NoHandler, Grant=NoHandler, Access=NoHandler> {
    state: State,
    authorization: Auth,
    grant: Grant,
    access: Access,
}

impl<State> CodeGrantEndpoint<State, NoHandler, NoHandler, NoHandler> {
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
        let result = flow.handle(msg.0);
        // TODO attach context to the message to handle this
        MessageResult(unimplemented!())
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
