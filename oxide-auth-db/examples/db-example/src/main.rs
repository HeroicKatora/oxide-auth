mod support;

use actix::{Actor, Addr, Context, Handler};
use actix_rt;
use actix_web::{middleware::Logger, web, App, HttpRequest, HttpServer};
use oxide_auth::{
    endpoint::{Endpoint, OwnerConsent, OwnerSolicitor, Solicitation},
    frontends::simple::endpoint::{ErrorInto, FnSolicitor, Generic, Vacant},
    primitives::prelude::{AuthMap, RandomGenerator, Scope, TokenMap},
};
use oxide_auth_actix::{
    Authorize, OAuthMessage, OAuthOperation, OAuthRequest, OAuthResource, OAuthResponse, Refresh,
    Resource, Token, WebError,
};
use std::{thread, env};
use oxide_auth_db::primitives::db_registrar::DBRegistrar;

static DENY_TEXT: &str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient&client_secret=test\">
here</a> to begin the authorization process.
</html>
";

struct State {
    endpoint: Generic<
        DBRegistrar,
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

async fn get_authorize(
    (req, state): (OAuthRequest, web::Data<Addr<State>>),
) -> Result<OAuthResponse, WebError> {
    // GET requests should not mutate server state and are extremely
    // vulnerable accidental repetition as well as Cross-Site Request
    // Forgery (CSRF).
    state.send(Authorize(req).wrap(Extras::AuthGet)).await?
}

async fn post_authorize(
    (r, req, state): (HttpRequest, OAuthRequest, web::Data<Addr<State>>),
) -> Result<OAuthResponse, WebError> {
    // Some authentication should be performed here in production cases
    state
        .send(Authorize(req).wrap(Extras::AuthPost(r.query_string().to_owned())))
        .await?
}

async fn token((req, state): (OAuthRequest, web::Data<Addr<State>>)) -> Result<OAuthResponse, WebError> {
    state.send(Token(req).wrap(Extras::Nothing)).await?
}

async fn refresh(
    (req, state): (OAuthRequest, web::Data<Addr<State>>),
) -> Result<OAuthResponse, WebError> {
    state.send(Refresh(req).wrap(Extras::Nothing)).await?
}

async fn index(
    (req, state): (OAuthResource, web::Data<Addr<State>>),
) -> Result<OAuthResponse, WebError> {
    match state
        .send(Resource(req.into_request()).wrap(Extras::Nothing))
        .await?
    {
        Ok(_grant) => Ok(OAuthResponse::ok()
            .content_type("text/plain")?
            .body("Hello world!")),
        Err(Ok(e)) => Ok(e.body(DENY_TEXT)),
        Err(Err(e)) => Err(e),
    }
}

async fn start_browser() -> () {
    let _ = thread::spawn(support::open_in_browser);
}

/// Example of a main function of an actix-web server supporting oauth.
pub fn main() {
    std::env::set_var(
        "RUST_LOG",
        "actix_example=info,actix_web=info,actix_http=info,actix_service=info",
    );
    std::env::set_var("REDIS_URL", "redis://localhost/3");
    std::env::set_var("MAX_POOL_SIZE", "32");

    std::env::set_var("CLIENT_PREFIX", "client:");

    env_logger::init();

    let redis_url = env::var("REDIS_URL").expect("REDIS_URL should be set");
    let max_pool_size = env::var("MAX_POOL_SIZE").unwrap_or("32".parse().unwrap());
    let client_prefix = env::var("CLIENT_PREFIX").unwrap_or("client:".parse().unwrap());

    let mut sys = actix_rt::System::new("HttpServerClient");

    // Start, then open in browser, don't care about this finishing.
    let _ = sys.block_on(start_browser());

    let oauth_db_service =
        DBRegistrar::new(redis_url, max_pool_size.parse::<u32>().unwrap(), client_prefix)
            .expect("Invalid URL to build DBRegistrar");

    let state = State::preconf_db_registrar(oauth_db_service).start();

    // Create the main server instance
    HttpServer::new(move || {
        App::new()
            .data(state.clone())
            .wrap(Logger::default())
            .service(
                web::resource("/authorize")
                    .route(web::get().to(get_authorize))
                    .route(web::post().to(post_authorize)),
            )
            .route("/token", web::post().to(token))
            .route("/refresh", web::post().to(refresh))
            .route("/", web::get().to(index))
    })
    .bind("localhost:8020")
    .expect("Failed to bind to socket")
    .run();

    support::dummy_client();
    // Run the rest of the system.
    let _ = sys.run();
}

impl State {
    pub fn preconf_db_registrar(db_service: DBRegistrar) -> Self {
        State {
            endpoint: Generic {
                // A redis db registrar, user can use regist() function to pre regist some clients.
                registrar: db_service,

                // Authorization tokens are 16 byte random keys to a memory hash map.
                authorizer: AuthMap::new(RandomGenerator::new(16)),
                // Bearer tokens are also random generated but 256-bit tokens, since they live longer
                // and this examples is somewhat paranoid.
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
        &'a mut self, solicitor: S,
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
                let solicitor = FnSolicitor(move |_: &mut OAuthRequest, pre_grant: Solicitation| {
                    // This will display a page to the user asking for his permission to proceed. The submitted form
                    // will then trigger the other authorization handler which actually completes the flow.
                    OwnerConsent::InProgress(
                        OAuthResponse::ok()
                            .content_type("text/html")
                            .unwrap()
                            .body(&crate::support::consent_page_html("/authorize".into(), pre_grant)),
                    )
                });

                op.run(self.with_solicitor(solicitor))
            }
            Extras::AuthPost(query_string) => {
                let solicitor = FnSolicitor(move |_: &mut OAuthRequest, _: Solicitation| {
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
