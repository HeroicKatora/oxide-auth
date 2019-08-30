use actix::{dev::MessageResponse, Actor, Context, Handler, Message};
use futures::future::IntoFuture;
use oxide_auth::{
    frontends::simple::endpoint::{Generic, Vacant},
    primitives::prelude::{
        AuthMap, Authorizer, Client, ClientMap, Issuer, RandomGenerator, Registrar, TokenMap,
    },
};

pub trait OxideOperation: Sized + 'static {
    type Item;
    type Error: std::fmt::Debug;
    type Future: IntoFuture<Item = Self::Item, Error = Self::Error>
        + MessageResponse<State, OxideMessage<Self>>;

    fn run(self, state: &mut State) -> Self::Future;

    fn wrap(self) -> OxideMessage<Self> {
        OxideMessage(self)
    }
}

pub struct State {
    pub registrar: ClientMap,
    pub authorizer: AuthMap<RandomGenerator>,
    pub issuer: TokenMap<RandomGenerator>,
}

pub struct OxideMessage<T>(T)
where
    T: OxideOperation;

impl<T> Message for OxideMessage<T>
where
    T: OxideOperation + 'static,
{
    type Result = Result<T::Item, T::Error>;
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
        }
    }

    pub fn endpoint<'a>(
        &'a mut self,
    ) -> Generic<impl Registrar + 'a, impl Authorizer + 'a, impl Issuer + 'a> {
        Generic {
            registrar: &mut self.registrar,
            authorizer: &mut self.authorizer,
            issuer: &mut self.issuer,
            // Solicitor configured later.
            solicitor: Vacant,
            // Scope configured later.
            scopes: Vacant,
            // `rocket::Response` is `Default`, so we don't need more configuration.
            response: Vacant,
        }
    }
}

impl Actor for State {
    type Context = Context<Self>;
}

impl<T> Handler<OxideMessage<T>> for State
where
    T: OxideOperation + 'static,
{
    type Result = T::Future;

    fn handle(&mut self, OxideMessage(op): OxideMessage<T>, _: &mut Self::Context) -> T::Future {
        op.run(self)
    }
}
