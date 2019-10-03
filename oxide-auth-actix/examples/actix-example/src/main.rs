mod support;

use actix::{Actor, Addr, Context, Handler};
use actix_web::{middleware::Logger, web, App, HttpRequest, HttpServer};
use futures::{future, Future};
use oxide_auth::{
    endpoint::{Endpoint, OwnerConsent, OwnerSolicitor, PreGrant},
    frontends::simple::endpoint::{ErrorInto, FnSolicitor, Generic, Vacant},
    primitives::prelude::{AuthMap, Client, ClientMap, Scope, TokenMap},
};
use oxide_auth_actix::{
    Authorize, OAuthMessage, OAuthOperation, OAuthRequest, OAuthResource, OAuthResponse, Refresh,
    Resource, Token, WebError,
};
use oxide_auth_ring::{generator::RandomGenerator, registrar::Pbkdf2};
use std::thread;

static DENY_TEXT: &str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

struct State {
    endpoint: Generic<
        ClientMap,
        AuthMap<RandomGenerator>,
        TokenMap<RandomGenerator>,
        Vacant,
        Vec<Scope>,
        fn() -> OAuthResponse,
    >,
}

enum Extras {
    AuthGet,
    AuthPost(String),
    Nothing,
}

/// Example of a main function of an actix-web server supporting oauth.
pub fn main() {
    std::env::set_var(
        "RUST_LOG",
        "actix_example=info,actix_web=info,actix_http=info,actix_service=info",
    );
    env_logger::init();

    let mut sys = actix::System::new("HttpServerClient");

    let state = State::preconfigured().start();

    // Create the main server instance
    HttpServer::new(move || {
        App::new()
            .data(state.clone())
            .wrap(Logger::default())
            .service(
                web::resource("/authorize")
                    .route(web::get().to_async(
                        |(req, state): (OAuthRequest, web::Data<Addr<State>>)| {
                            // GET requests should not mutate server state and are extremely
                            // vulnerable accidental repetition as well as Cross-Site Request
                            // Forgery (CSRF).
                            state
                                .send(Authorize(req).wrap(Extras::AuthGet))
                                .map_err(WebError::from)
                        },
                    ))
                    .route(web::post().to_async(
                        |(r, req, state): (HttpRequest, OAuthRequest, web::Data<Addr<State>>)| {
                            // Some authentication should be performed here in production cases
                            state
                                .send(
                                    Authorize(req)
                                        .wrap(Extras::AuthPost(r.query_string().to_owned())),
                                )
                                .map_err(WebError::from)
                        },
                    )),
            )
            .route(
                "/token",
                web::post().to_async(|(req, state): (OAuthRequest, web::Data<Addr<State>>)| {
                    state
                        .send(Token(req).wrap(Extras::Nothing))
                        .map_err(WebError::from)
                }),
            )
            .route(
                "/refresh",
                web::post().to_async(|(req, state): (OAuthRequest, web::Data<Addr<State>>)| {
                    state
                        .send(Refresh(req).wrap(Extras::Nothing))
                        .map_err(WebError::from)
                }),
            )
            .route(
                "/",
                web::get().to_async(|(req, state): (OAuthResource, web::Data<Addr<State>>)| {
                    state
                        .send(Resource(req.into_request()).wrap(Extras::Nothing))
                        .map_err(WebError::from)
                        .and_then(|res| match res {
                            Ok(_grant) => Ok(OAuthResponse::ok()
                                .content_type("text/plain")?
                                .body("Hello world!")),
                            Err(Ok(response)) => Ok(response.body(DENY_TEXT)),
                            Err(Err(e)) => Err(e.into()),
                        })
                }),
            )
    })
    .bind("localhost:8020")
    .expect("Failed to bind to socket")
    .start();

    support::dummy_client();

    // Start, then open in browser, don't care about this finishing.
    let _: Result<(), ()> = sys.block_on(future::lazy(|| {
        let _ = thread::spawn(support::open_in_browser);
        future::ok(())
    }));

    // Run the rest of the system.
    let _ = sys.run();
}

impl State {
    pub fn preconfigured() -> Self {
        let mut registrar = ClientMap::new(Pbkdf2::default());
        registrar.register_client(Client::public(
            "LocalClient",
            "http://localhost:8021/endpoint".parse().unwrap(),
            "default-scope".parse().unwrap(),
        ));

        State {
            endpoint: Generic {
                // A registrar with one pre-registered client
                registrar,
                // Authorization tokens are 16 byte random keys to a memory hash map.
                authorizer: AuthMap::new(RandomGenerator::new(16)),
                // Bearer tokens are also random generated but 256-bit tokens, since they live longer
                // and this example is somewhat paranoid.
                //
                // We could also use a `TokenSigner::ephemeral` here to create signed tokens which can
                // be read and parsed by anyone, but not maliciously created. However, they can not be
                // revoked and thus don't offer even longer lived refresh tokens.
                issuer: TokenMap::new(RandomGenerator::new(16)),

                solicitor: Vacant,

                // A single scope that will guard resources for this endpoint
                scopes: vec!["default-scope".parse().unwrap()],

                response: OAuthResponse::ok,
            },
        }
    }

    pub fn with_solicitor<'a, S>(
        &'a mut self,
        solicitor: S,
    ) -> impl Endpoint<OAuthRequest, Error = WebError> + 'a
    where
        S: OwnerSolicitor<OAuthRequest> + 'static,
    {
        ErrorInto::new(Generic {
            authorizer: &mut self.endpoint.authorizer,
            registrar: &mut self.endpoint.registrar,
            issuer: &mut self.endpoint.issuer,
            solicitor,
            scopes: &mut self.endpoint.scopes,
            response: OAuthResponse::ok,
        })
    }
}

impl Actor for State {
    type Context = Context<Self>;
}

impl<Op> Handler<OAuthMessage<Op, Extras>> for State
where
    Op: OAuthOperation,
{
    type Result = Result<Op::Item, Op::Error>;

    fn handle(&mut self, msg: OAuthMessage<Op, Extras>, _: &mut Self::Context) -> Self::Result {
        let (op, ex) = msg.into_inner();

        match ex {
            Extras::AuthGet => {
                let solicitor = FnSolicitor(move |_: &mut OAuthRequest, pre_grant: &PreGrant| {
                    // This will display a page to the user asking for his permission to proceed. The submitted form
                    // will then trigger the other authorization handler which actually completes the flow.
                    OwnerConsent::InProgress(
                        OAuthResponse::ok().content_type("text/html").unwrap().body(
                            &crate::support::consent_page_html("/authorize".into(), pre_grant),
                        ),
                    )
                });

                op.run(self.with_solicitor(solicitor))
            }
            Extras::AuthPost(query_string) => {
                let solicitor = FnSolicitor(move |_: &mut OAuthRequest, _: &PreGrant| {
                    if query_string.contains("allow") {
                        OwnerConsent::Authorized("dummy user".to_owned())
                    } else {
                        OwnerConsent::Denied
                    }
                });

                op.run(self.with_solicitor(solicitor))
            }
            _ => op.run(&mut self.endpoint),
        }
    }
}
