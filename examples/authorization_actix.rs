extern crate actix;
extern crate actix_web;
extern crate futures;
extern crate oxide_auth;
extern crate url;

mod support;

use actix::{Actor, Addr};
use actix_web::{server, App, HttpRequest, HttpResponse};
use futures::Future;

use oxide_auth::frontends::actix::{AsActor, OAuth, OAuthFailure, OAuthResponse, OwnerConsent, PreGrant, ResourceProtection};
use oxide_auth::frontends::actix::{authorization, access_token, resource};
use oxide_auth::frontends::simple::endpoint::FnSolicitor;
use oxide_auth::primitives::prelude::*;

use support::actix::dummy_client;
use support::{consent_page_html, open_in_browser};

static DENY_TEXT: &str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

#[derive(Clone)]
struct State {
    registrar: Addr<AsActor<ClientMap>>,
    authorizer: Addr<AsActor<Storage<RandomGenerator>>>,
    issuer: Addr<AsActor<TokenSigner>>,
    scopes: &'static [Scope],
}

/// Example of a main function of a rouille server supporting oauth.
pub fn main() {
    let sys = actix::System::new("HttpServerClient");

    let mut clients  = ClientMap::new();
    // Register a dummy client instance
    let client = Client::public("LocalClient", // Client id
        "http://localhost:8021/endpoint".parse().unwrap(), // Redirection url
        "default".parse().unwrap()); // Allowed client scope
    clients.register_client(client);

    let authorizer = Storage::new(RandomGenerator::new(16));
    let issuer = TokenSigner::ephemeral();

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
            .resource("/authorize", |r| {
                r.get().a(|req: &HttpRequest<State>| {
                    let state = req.state().clone();
                    req.oauth2()
                        .and_then(|request| authorization(
                            state.registrar,
                            state.authorizer,
                            FnSolicitor(|_: &mut _, grant: &_| handle_get(grant)),
                            request,
                            OAuthResponse::default()))
                        .map(|response| response.get_or_consent_with(consent_form))
                        .map_err(OAuthFailure)
                });
                r.post().a(|req: &HttpRequest<State>| {
                    let state = req.state().clone();
                    let denied = req.query_string().contains("deny");
                    req.oauth2()
                        .and_then(move |request| authorization(
                            state.registrar,
                            state.authorizer,
                            FnSolicitor(move |_: &mut _, grant: &_| handle_post(denied, grant)),
                            request,
                            OAuthResponse::default()))
                        .map(OAuthResponse::unwrap)
                        .map_err(OAuthFailure)
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
                    .map_err(OAuthFailure)
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
                    .map(|()| HttpResponse::Ok()
                        .content_type("text/plain")
                        .body("Hello world!"))
                    .or_else(|result| match result {
                        ResourceProtection::Respond(response) => {
                            let mut response = response.unwrap();
                            response.set_body(DENY_TEXT);
                            Ok(response)
                        },
                        ResourceProtection::Error(err) => Err(OAuthFailure(err)),
                    })
            }))
        )
        .bind("localhost:8020")
        .expect("Failed to bind to socket")
        .start();

    server::new(|| App::new().handler("/endpoint", dummy_client))
        .bind("localhost:8021")
        .expect("Failed to start dummy client")
        .start();

    actix::System::current().arbiter()
        .do_send(actix::msgs::Execute::new(
            || -> Result<(), ()> { Ok(open_in_browser()) }));
    let _ = sys.run();
}

fn consent_form(grant: PreGrant) -> HttpResponse {
    let text = consent_page_html("/authorize".into(), grant);
    HttpResponse::Ok()
        .content_type("text/html")
        .body(text)
}

/// A simple implementation of the first part of an authentication handler. This will
/// display a page to the user asking for his permission to proceed. The submitted form
/// will then trigger the other authorization handler which actually completes the flow.
fn handle_get(grant: &PreGrant) -> OwnerConsent<OAuthResponse> {
    OwnerConsent::InProgress(OAuthResponse::consent_form(grant.clone()))
}

/// Handle form submission by a user, completing the authorization flow. The resource owner
/// either accepted or denied the request.
fn handle_post(denied: bool, _: &PreGrant) -> OwnerConsent<OAuthResponse> {
    // No real user authentication is done here, in production you SHOULD use session keys or equivalent
    if denied {
        OwnerConsent::Denied
    } else {
        OwnerConsent::Authorized("dummy user".to_string())
    }
}
