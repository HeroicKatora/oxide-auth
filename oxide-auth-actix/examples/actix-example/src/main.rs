mod support;

use std::{
    sync::{Arc, Mutex},
    thread,
};

use actix_web::{error::BlockingError, middleware::Logger, web, App, HttpRequest, HttpServer};
use futures::{future, Future};
use oxide_auth_actix::{OAuthRequest, OAuthResponse, WebError};
use oxide_auth::{
    endpoint::{OwnerConsent, PreGrant},
    frontends::{
        simple::endpoint::{FnSolicitor, Generic, Vacant},
    },
    primitives::prelude::*,
};

static DENY_TEXT: &str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

struct State {
    registrar: Mutex<ClientMap>,
    authorizer: Mutex<AuthMap<RandomGenerator>>,
    issuer: Mutex<TokenMap<RandomGenerator>>,
}

impl State {
    pub fn preconfigured() -> Self {
        State {
            registrar: Mutex::new(
                vec![Client::public(
                    "LocalClient",
                    "http://localhost:8021/endpoint".parse().unwrap(),
                    "default-scope".parse().unwrap(),
                )]
                .into_iter()
                .collect(),
            ),
            // Authorization tokens are 16 byte random keys to a memory hash map.
            authorizer: Mutex::new(AuthMap::new(RandomGenerator::new(16))),
            // Bearer tokens are also random generated but 256-bit tokens, since they live longer
            // and this example is somewhat paranoid.
            //
            // We could also use a `TokenSigner::ephemeral` here to create signed tokens which can
            // be read and parsed by anyone, but not maliciously created. However, they can not be
            // revoked and thus don't offer even longer lived refresh tokens.
            issuer: Mutex::new(TokenMap::new(RandomGenerator::new(16))),
        }
    }

    pub fn endpoint(&self) -> Generic<impl Registrar + '_, impl Authorizer + '_, impl Issuer + '_> {
        Generic {
            registrar: self.registrar.lock().unwrap(),
            authorizer: self.authorizer.lock().unwrap(),
            issuer: self.issuer.lock().unwrap(),
            // Solicitor configured later.
            solicitor: Vacant,
            // Scope configured later.
            scopes: Vacant,
            // `rocket::Response` is `Default`, so we don't need more configuration.
            response: Vacant,
        }
    }
}

/// Example of a main function of a rouille server supporting oauth.
pub fn main() {
    std::env::set_var(
        "RUST_LOG",
        "actix_example=info,actix_web=info,actix_http=info,actix_service=info",
    );
    env_logger::init();
    let mut sys = actix::System::new("HttpServerClient");

    let mut clients = ClientMap::new();
    // Register a dummy client instance
    let client = Client::public(
        "LocalClient",                                     // Client id
        "http://localhost:8021/endpoint".parse().unwrap(), // Redirection url
        "default".parse().unwrap(),
    ); // Allowed client scope
    clients.register_client(client);

    let state = Arc::new(State::preconfigured());

    // Create the main server instance
    HttpServer::new(move || {
        App::new()
            .data(state.clone())
            .wrap(Logger::default())
            .service(
                web::resource("/authorize")
                    .route(web::get().to_async(
                        |(req, state): (OAuthRequest, web::Data<Arc<State>>)| {
                            web::block(move || {
                                state
                                    .endpoint()
                                    .with_solicitor(FnSolicitor(consent_form))
                                    .to_authorization()
                                    .execute(req)
                            })
                            .map_err(WebError::from)
                        },
                    ))
                    .route(web::post().to_async(
                        |(r, req, state): (HttpRequest, OAuthRequest, web::Data<Arc<State>>)| {
                            let allowed = r.query_string().contains("allow");
                            web::block(move || {
                                state
                                    .endpoint()
                                    .with_solicitor(FnSolicitor(move |_: &mut _, grant: &_| {
                                        consent_decision(allowed, grant)
                                    }))
                                    .to_authorization()
                                    .execute(req)
                            })
                            .map_err(WebError::from)
                        },
                    )),
            )
            .service(web::resource("/token").route(web::post().to_async(
                |(req, state): (OAuthRequest, web::Data<Arc<State>>)| {
                    web::block(move || state.endpoint().to_access_token().execute(req))
                        .map_err(WebError::from)
                },
            )))
            .service(web::resource("/refresh").route(web::post().to_async(
                |(req, state): (OAuthRequest, web::Data<Arc<State>>)| {
                    web::block(move || state.endpoint().to_refresh().execute(req))
                        .map_err(WebError::from)
                },
            )))
            .route(
                "/",
                web::get().to_async(|(req, state): (OAuthRequest, web::Data<Arc<State>>)| {
                    web::block(move || {
                        state
                            .endpoint()
                            .with_scopes(vec!["default-scope".parse().unwrap()])
                            .to_resource()
                            .execute(req)
                    })
                    .then(|res| match res {
                        Ok(_grant) => Ok(OAuthResponse::ok()
                            .content_type("text/plain")?
                            .body("Hello world!")),
                        Err(BlockingError::Error(Ok(response))) => Ok(response.body(DENY_TEXT)),
                        Err(BlockingError::Error(Err(e))) => Err(e.into()),
                        Err(BlockingError::Canceled) => Err(WebError::Canceled),
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

/// A simple implementation of the first part of an authentication handler.
///
/// This will display a page to the user asking for his permission to proceed. The submitted form
/// will then trigger the other authorization handler which actually completes the flow.
fn consent_form(_: &mut OAuthRequest, grant: &PreGrant) -> OwnerConsent<OAuthResponse> {
    OwnerConsent::InProgress(
        OAuthResponse::ok()
            .content_type("text/html")
            .unwrap()
            .body(&support::consent_page_html("/authorize".into(), &grant)),
    )
}

/// Handle form submission by a user, completing the authorization flow.
///
/// The resource owner either accepted or denied the request.
fn consent_decision(allowed: bool, _: &PreGrant) -> OwnerConsent<OAuthResponse> {
    // No real user authentication is done here, in production you SHOULD use session keys or equivalent
    if allowed {
        OwnerConsent::Authorized("dummy user".to_string())
    } else {
        OwnerConsent::Denied
    }
}
