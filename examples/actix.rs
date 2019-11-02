extern crate actix;
extern crate actix_web;
extern crate futures;
extern crate oxide_auth;
extern crate url;

#[path = "support/actix.rs"]
mod support;

use std::thread;

use actix::{Actor, Addr};
use actix_web::{server, App, HttpRequest, HttpResponse};
use actix_web::middleware::Logger;
use futures::{Future, future};

use oxide_auth::frontends::actix::{AsActor, OAuth, OAuthFailure, OAuthResponse, OwnerConsent, PreGrant, ResourceProtection};
use oxide_auth::frontends::actix::{authorization, access_token, refresh, resource};
use oxide_auth::frontends::simple::endpoint::FnSolicitor;
use oxide_auth::primitives::prelude::*;

static DENY_TEXT: &str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

#[derive(Clone)]
struct State {
    registrar: Addr<AsActor<ClientMap>>,
    authorizer: Addr<AsActor<AuthMap<RandomGenerator>>>,
    issuer: Addr<AsActor<TokenMap<RandomGenerator>>>,
    scopes: &'static [Scope],
}

/// Example of a main function of a actix server supporting oauth.
pub fn main() {
    let mut sys = actix::System::new("HttpServerClient");

    let mut clients  = ClientMap::new();
    // Register a dummy client instance
    let client = Client::public("LocalClient", // Client id
        "http://localhost:8021/endpoint".parse().unwrap(), // Redirection url
        "default".parse().unwrap()); // Allowed client scope
    clients.register_client(client);

    // Authorization tokens are 16 byte random keys to a memory hash map.
    let authorizer = AuthMap::new(RandomGenerator::new(16));

    // Bearer tokens are also random generated but 256-bit tokens, since they live longer and this
    // example is somewhat paranoid.
    //
    // We could also use a `TokenSigner::ephemeral` here to create signed tokens which can be read
    // and parsed by anyone, but not maliciously created. However, they can not be revoked and thus
    // don't offer even longer lived refresh tokens.
    let issuer = TokenMap::new(RandomGenerator::new(16));

    let scopes = vec!["default".parse().unwrap()].into_boxed_slice();
    // Emulate static initialization for complex type
    let scopes: &'static _ = Box::leak(scopes);

    let state = State {
        registrar: AsActor(clients).start(),
        authorizer: AsActor(authorizer).start(),
        issuer: AsActor(issuer).start(),
        scopes,
    };

    // Create the main server instance
    server::new(
        move || App::with_state(state.clone())
            .middleware(Logger::default())
            .resource("/authorize", |r| {
                r.get().a(|req: &HttpRequest<State>| {
                    let state = req.state().clone();
                    req.oauth2()
                        .and_then(|request| authorization(
                            state.registrar,
                            state.authorizer,
                            FnSolicitor(|_: &mut _, grant: &_| in_progress_response(grant)),
                            request,
                            OAuthResponse::default()))
                        .map(|response| response.get_or_consent_with(consent_form))
                        .map_err(OAuthFailure::from)
                });
                r.post().a(|req: &HttpRequest<State>| {
                    let state = req.state().clone();
                    let allowed = req.query_string().contains("allow");
                    req.oauth2()
                        .and_then(move |request| authorization(
                            state.registrar,
                            state.authorizer,
                            FnSolicitor(move |_: &mut _, grant: &_| consent_decision(allowed, grant)),
                            request,
                            OAuthResponse::default()))
                        .map(OAuthResponse::unwrap)
                        .map_err(OAuthFailure::from)
                });
            })
            .resource("/token", |r| r.post().a(|req: &HttpRequest<State>| {
                let state = req.state().clone();
                req.oauth2()
                    .and_then(|request| access_token(
                            state.registrar,
                            state.authorizer,
                            state.issuer,
                            request,
                            OAuthResponse::default()))
                    .map(OAuthResponse::unwrap)
                    .map_err(OAuthFailure::from)
            }))
            .resource("/refresh", |r| r.post().a(|req: &HttpRequest<State>| {
                let state = req.state().clone();
                req.oauth2()
                    .and_then(|request| refresh(
                            state.registrar,
                            state.issuer,
                            request,
                            OAuthResponse::default()))
                    .map(OAuthResponse::unwrap)
                    .map_err(OAuthFailure::from)
            }))
            .resource("/", |r| r.get().a(|req: &HttpRequest<State>| {
                let state = req.state().clone();
                req.oauth2()
                    .map_err(ResourceProtection::Error)
                    .and_then(|request| resource(
                            state.issuer,
                            state.scopes,
                            request,
                            OAuthResponse::default()))
                    // Any accepted grant is good enough.
                    .map(|_grant| HttpResponse::Ok()
                        .content_type("text/plain")
                        .body("Hello world!"))
                    .or_else(|result| match result {
                        ResourceProtection::Respond(response) => {
                            let mut response = response.unwrap();
                            response.set_body(DENY_TEXT);
                            Ok(response)
                        },
                        ResourceProtection::Error(err) => Err(OAuthFailure::from(err)),
                    })
            }))
        )
        .bind("localhost:8020")
        .expect("Failed to bind to socket")
        .start();

    server::new(support::dummy_client)
        .bind("localhost:8021")
        .expect("Failed to start dummy client")
        .start();

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
fn consent_form(grant: PreGrant) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html")
        .body(support::consent_page_html("/authorize".into(), &grant))
}

fn in_progress_response(grant: &PreGrant) -> OwnerConsent<OAuthResponse> {
    OwnerConsent::InProgress(OAuthResponse::consent_form(grant.clone()))
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
