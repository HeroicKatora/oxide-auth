mod support;

use actix::{Actor, Addr, Context, Handler};
use actix_web::{middleware::Logger, web, App, HttpServer};
use futures::{future, Future};
use oxide_auth::{
    endpoint::{
        Endpoint, OAuthError, OwnerConsent, OwnerSolicitor, PreGrant, QueryParameter, Scopes,
        Template,
    },
    primitives::prelude::{
        AuthMap, Authorizer, Client, ClientMap, Issuer, RandomGenerator, Registrar, Scope, TokenMap,
    },
};
use oxide_auth_actix::{
    Authorize, OAuthRequest, OAuthResponse, OxideMessage, OxideOperation, Refresh, Resource, Token,
    WebError,
};
use std::thread;

static DENY_TEXT: &str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

struct State {
    registrar: ClientMap,
    authorizer: AuthMap<RandomGenerator>,
    issuer: TokenMap<RandomGenerator>,
    solicitor: AllowedSolicitor,
    scopes: Vec<Scope>,
}

struct AllowedSolicitor;

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
                            state.send(Authorize(req).wrap()).map_err(WebError::from)
                        },
                    ))
                    .route(web::post().to_async(
                        |(req, state): (OAuthRequest, web::Data<Addr<State>>)| {
                            state.send(Authorize(req).wrap()).map_err(WebError::from)
                        },
                    )),
            )
            .service(web::resource("/token").route(web::post().to_async(
                |(req, state): (OAuthRequest, web::Data<Addr<State>>)| {
                    state.send(Token(req).wrap()).map_err(WebError::from)
                },
            )))
            .service(web::resource("/refresh").route(web::post().to_async(
                |(req, state): (OAuthRequest, web::Data<Addr<State>>)| {
                    state.send(Refresh(req).wrap()).map_err(WebError::from)
                },
            )))
            .route(
                "/",
                web::get().to_async(|(req, state): (OAuthRequest, web::Data<Addr<State>>)| {
                    state
                        .send(Resource(req).wrap())
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
        State {
            // A registrar with one pre-registered client
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

impl OwnerSolicitor<OAuthRequest> for AllowedSolicitor {
    fn check_consent(
        &mut self,
        req: &mut OAuthRequest,
        grant: &PreGrant,
    ) -> OwnerConsent<OAuthResponse> {
        // No real user authentication is done here, in production you SHOULD use session keys or equivalent
        if let Some(query) = req.query() {
            if let Some(v) = query.unique_value("allow") {
                if v == "true" {
                    OwnerConsent::Authorized("dummy user".to_string())
                } else {
                    OwnerConsent::Denied
                }
            } else if query.unique_value("deny").is_some() {
                OwnerConsent::Denied
            } else {
                progress(grant)
            }
        } else {
            progress(grant)
        }
    }
}

// This will display a page to the user asking for his permission to proceed. The submitted form
// will then trigger the other authorization handler which actually completes the flow.
fn progress(grant: &PreGrant) -> OwnerConsent<OAuthResponse> {
    OwnerConsent::InProgress(OAuthResponse::ok().content_type("text/html").unwrap().body(
        &crate::support::consent_page_html("/authorize".into(), &grant),
    ))
}
