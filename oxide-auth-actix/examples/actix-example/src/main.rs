mod operations;
mod state;
mod support;

use self::{
    operations::{GetAuthorize, GetResource, PostAuthorize, PostRefresh, PostToken},
    state::{OxideOperation, State},
};

use std::thread;

use actix::{Actor, Addr};
use actix_web::{middleware::Logger, web, App, HttpRequest, HttpServer};
use futures::{future, Future};
use oxide_auth_actix::{OAuthRequest, OAuthResponse, WebError};

static DENY_TEXT: &str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

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
                            state.send(GetAuthorize(req).wrap()).map_err(WebError::from)
                        },
                    ))
                    .route(web::post().to_async(
                        |(r, req, state): (HttpRequest, OAuthRequest, web::Data<Addr<State>>)| {
                            state
                                .send(PostAuthorize(req, r.query_string().contains("allow")).wrap())
                                .map_err(WebError::from)
                        },
                    )),
            )
            .service(web::resource("/token").route(web::post().to_async(
                |(req, state): (OAuthRequest, web::Data<Addr<State>>)| {
                    state.send(PostToken(req).wrap()).map_err(WebError::from)
                },
            )))
            .service(web::resource("/refresh").route(web::post().to_async(
                |(req, state): (OAuthRequest, web::Data<Addr<State>>)| {
                    state.send(PostRefresh(req).wrap()).map_err(WebError::from)
                },
            )))
            .route(
                "/",
                web::get().to_async(|(req, state): (OAuthRequest, web::Data<Addr<State>>)| {
                    state
                        .send(GetResource(req).wrap())
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
