extern crate iron;
extern crate oxide_auth;
extern crate router;

use std::sync::{Arc, Mutex};
use std::thread::spawn;

use iron::{Iron, Request, Response};
use iron::middleware::Handler;

use oxide_auth::frontends::simple::endpoint::Generic;
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
    let mut router = router::Router::new();
    router.get("/authorize", |request: &mut Request| {
        Ok(Response::new())
    }, "authorization_get");
    router.post("/authorize", |request: &mut Request| {
        Ok(Response::new())
    }, "authorization_post");
    router.get("/token", |request: &mut Request| {
        Ok(Response::new())
    }, "token");
    router.get("/", |request: &mut Request| {
        Ok(Response::new())
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
}
