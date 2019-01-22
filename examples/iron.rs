extern crate iron;
extern crate oxide_auth;
extern crate router;

use std::sync::{Arc, Mutex};
use std::thread::spawn;

use iron::{Iron, Request, Response};
use iron::headers::ContentType;
use iron::status::Status;
use iron::middleware::Handler;

use oxide_auth::endpoint::{OwnerConsent};
use oxide_auth::frontends::simple::endpoint::{FnSolicitor, Generic, Vacant};
use oxide_auth::primitives::prelude::*;

#[path = "support/iron.rs"]
mod support;

struct EndpointState {
    registrar: Mutex<ClientMap>,
    authorizer: Mutex<AuthMap<RandomGenerator>>,
    issuer: Mutex<TokenSigner>,
}

fn main_router() -> impl Handler + 'static {
    let state = Arc::new(EndpointState::preconfigured());

    // One clone for each of the move-closures below.
    let (auth_get_state, auth_post_state, token_state, get_state) =
        (state.clone(), state.clone(), state.clone(), state.clone());
    let mut router = router::Router::new();
    router.get("/authorize", move |request: &mut Request| {
        let state = auth_get_state.clone();
        let response = state.endpoint()
            .with_solicitor(FnSolicitor(consent_form))
            .to_authorization()
            .execute(request)?;
        Ok(response)
    }, "authorization_get");
    router.post("/authorize", move |request: &mut Request| {
        let state = auth_post_state.clone();
        let response = state.endpoint()
            .with_solicitor(FnSolicitor(consent_decision))
            .to_authorization()
            .execute(request)?;
        Ok(response)
    }, "authorization_post");
    router.post("/token", move |request: &mut Request| {
        let state = token_state.clone();
        let response = state.endpoint()
            .to_access_token()
            .execute(request)?;
        Ok(response)
    }, "token");
    router.get("/", move |request: &mut Request| {
        let state = get_state.clone();
        let protect = state.endpoint()
            .with_scopes(vec!["default-scope".parse().unwrap()])
            .to_resource()
            .execute(request);

        let _grant = match protect {
            Ok(grant) => grant,
            Err(Ok(mut response)) => {
                response.headers.set(ContentType::html());
                response.body = Some(Box::new(EndpointState::DENY_TEXT));
                return Ok(response)
            },
            Err(Err(error)) => return Err(error.into()),
        };

        Ok(Response::with((Status::Ok, "Hello, world!")))
    }, "protected");

    router
}

fn main() {
    let server = spawn(|| {
        Iron::new(main_router())
            .http("127.0.0.1:8020")
            .expect("Failed to launch authorization server");
    });

    let client = spawn(|| {
        Iron::new(support::dummy_client())
            .http("127.0.0.1:8021")
            .expect("Failed to launch client");
    });

    support::open_in_browser();

    server.join().unwrap();
    client.join().unwrap();
}

impl EndpointState {
    const DENY_TEXT: &'static str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

    fn preconfigured() -> Self {
        EndpointState {
            registrar: Mutex::new(vec![
                Client::public("LocalClient",
                    "http://localhost:8021/endpoint".parse().unwrap(),
                    "default-scope".parse().unwrap())
            ].into_iter().collect()),
            authorizer: Mutex::new(AuthMap::new(RandomGenerator::new(16))),
            issuer: Mutex::new(TokenSigner::ephemeral()),
        }
    }

    /// In larger app, you'd likey wrap it in your own Endpoint instead of `Generic`.
    pub fn endpoint(&self) -> Generic<impl Registrar + '_, impl Authorizer + '_, impl Issuer + '_, Vacant, Vacant, fn() -> Response> {
        Generic {
            registrar: self.registrar.lock().unwrap(),
            authorizer: self.authorizer.lock().unwrap(),
            issuer: self.issuer.lock().unwrap(),
            // Solicitor configured later.
            solicitor: Vacant,
            // Scope configured later.
            scopes: Vacant,
            // `rocket::Response` is `Default`, so we don't need more configuration.
            response: Response::new,
        }
    }
}

fn consent_form(_: &mut &mut Request, grant: &PreGrant) -> OwnerConsent<Response> {
    let mut response = Response::with(Status::Ok);
    response.headers.set(ContentType::html());
    response.body = Some(Box::new(support::consent_page_html("/authorize", grant)));
    OwnerConsent::InProgress(response)
}

fn consent_decision(request: &mut &mut Request, _: &PreGrant) -> OwnerConsent<Response> {
    // Consider authentiating the better
    let allowed = request.url.as_ref()
        .query_pairs()
        .any(|(key, _)| key == "allow");
    if allowed { 
        OwnerConsent::Authorized("dummy user".into()) 
    } else {
        OwnerConsent::Denied 
    }
}
