use actix::{Actor, Context, Handler};
use oxide_auth::{
    endpoint::{Endpoint, OAuthError, OwnerSolicitor, Scopes, Template},
    primitives::prelude::{
        AuthMap, Authorizer, Client, ClientMap, Issuer, RandomGenerator, Registrar, Scope, TokenMap,
    },
};
use oxide_auth_actix::{OAuthRequest, OAuthResponse, OxideMessage, OxideOperation, WebError};

use crate::AllowedSolicitor;

pub struct State {
    registrar: ClientMap,
    authorizer: AuthMap<RandomGenerator>,
    issuer: TokenMap<RandomGenerator>,
    solicitor: AllowedSolicitor,
    scopes: Vec<Scope>,
}

impl State {
    pub fn preconfigured() -> Self {
        State {
            registrar: vec![Client::public(
                "LocalClient",
                "http://localhost:8021/endpoint".parse().unwrap(),
                "default-scope".parse().unwrap(),
            )]
            .into_iter()
            .collect(),
            // Authorization tokens are 16 byte random keys to a memory hash map.
            authorizer: AuthMap::new(RandomGenerator::new(16)),
            // Bearer tokens are also random generated but 256-bit tokens, since they live longer
            // and this example is somewhat paranoid.
            //
            // We could also use a `TokenSigner::ephemeral` here to create signed tokens which can
            // be read and parsed by anyone, but not maliciously created. However, they can not be
            // revoked and thus don't offer even longer lived refresh tokens.
            issuer: TokenMap::new(RandomGenerator::new(16)),

            // A custom solicitor which bases it's progress, allow, or deny on the query parameters
            // from the request
            solicitor: AllowedSolicitor,

            // A single scope that will guard resources for this endpoint
            scopes: vec!["default-scope".parse().unwrap()],
        }
    }
}

impl Endpoint<OAuthRequest> for State {
    type Error = WebError;

    fn registrar(&self) -> Option<&dyn Registrar> {
        Some(&self.registrar)
    }

    fn authorizer_mut(&mut self) -> Option<&mut dyn Authorizer> {
        Some(&mut self.authorizer)
    }

    fn issuer_mut(&mut self) -> Option<&mut dyn Issuer> {
        Some(&mut self.issuer)
    }

    fn owner_solicitor(&mut self) -> Option<&mut dyn OwnerSolicitor<OAuthRequest>> {
        Some(&mut self.solicitor)
    }

    fn scopes(&mut self) -> Option<&mut dyn Scopes<OAuthRequest>> {
        Some(&mut self.scopes)
    }

    fn response(&mut self, _: &mut OAuthRequest, _: Template) -> Result<OAuthResponse, WebError> {
        Ok(OAuthResponse::ok())
    }

    fn error(&mut self, err: OAuthError) -> WebError {
        err.into()
    }

    fn web_error(&mut self, err: WebError) -> WebError {
        err
    }
}

impl Actor for State {
    type Context = Context<Self>;
}

impl<T> Handler<OxideMessage<T>> for State
where
    T: OxideOperation + 'static,
    T::Item: 'static,
    T::Error: 'static,
{
    type Result = Result<T::Item, T::Error>;

    fn handle(&mut self, msg: OxideMessage<T>, _: &mut Self::Context) -> Self::Result {
        msg.into_inner().run(self)
    }
}
