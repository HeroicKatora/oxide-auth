extern crate iron;
extern crate oxide_auth;
extern crate router;

use std::sync::{Arc, Mutex};
use std::thread::spawn;

use iron::headers::ContentType;
use iron::middleware::Handler;
use iron::status::Status;
use iron::{Iron, Request, Response};

use oxide_auth::endpoint::OwnerConsent;
use oxide_auth::frontends::{
    iron::{OAuthError, OAuthRequest, OAuthResponse},
    simple::endpoint::{FnSolicitor, Generic, Vacant},
};
use oxide_auth::primitives::prelude::*;

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
    router.get(
        "/authorize",
        move |request: &mut Request| {
            let state = auth_get_state.clone();
            let response = state
                .endpoint()
                .with_solicitor(FnSolicitor(consent_form))
                .to_authorization()
                .execute(OAuthRequest(request))
                .map_err(|e| {
                    let e: OAuthError = e.into();
                    e.0
                })?;
            Ok(response.into())
        },
        "authorization_get",
    );
    router.post(
        "/authorize",
        move |request: &mut Request| {
            let state = auth_post_state.clone();
            let response = state
                .endpoint()
                .with_solicitor(FnSolicitor(consent_decision))
                .to_authorization()
                .execute(OAuthRequest(request))
                .map_err(|e| {
                    let e: OAuthError = e.into();
                    e.0
                })?;
            Ok(response.into())
        },
        "authorization_post",
    );
    router.post(
        "/token",
        move |request: &mut Request| {
            let state = token_state.clone();
            let response = state
                .endpoint()
                .to_access_token()
                .execute(OAuthRequest(request))
                .map_err(|e| {
                    let e: OAuthError = e.into();
                    e.0
                })?;
            Ok(response.into())
        },
        "token",
    );
    router.get(
        "/",
        move |request: &mut Request| {
            let state = get_state.clone();
            let protect = state
                .endpoint()
                .with_scopes(vec!["default-scope".parse().unwrap()])
                .to_resource()
                .execute(OAuthRequest(request));

            let _grant = match protect {
                Ok(grant) => grant,
                Err(Ok(mut response)) => {
                    response.0.headers.set(ContentType::html());
                    response.0.body = Some(Box::new(EndpointState::DENY_TEXT));
                    return Ok(response.into());
                }
                Err(Err(error)) => {
                    let error: OAuthError = error.into();
                    return Err(error.0);
                }
            };

            Ok(Response::with((Status::Ok, "Hello, world!")))
        },
        "protected",
    );

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
            registrar: Mutex::new(
                vec![Client::public(
                    "LocalClient",
                    "http://localhost:8021/endpoint".parse().unwrap(),
                    "default-scope".parse().unwrap(),
                )]
                .into_iter()
                .collect(),
            ),
            authorizer: Mutex::new(AuthMap::new(RandomGenerator::new(16))),
            issuer: Mutex::new(TokenSigner::ephemeral()),
        }
    }

    /// In larger app, you'd likey wrap it in your own Endpoint instead of `Generic`.
    pub fn endpoint(
        &self,
    ) -> Generic<
        impl Registrar + '_,
        impl Authorizer + '_,
        impl Issuer + '_,
        Vacant,
        Vacant,
        fn() -> OAuthResponse,
    > {
        Generic {
            registrar: self.registrar.lock().unwrap(),
            authorizer: self.authorizer.lock().unwrap(),
            issuer: self.issuer.lock().unwrap(),
            // Solicitor configured later.
            solicitor: Vacant,
            // Scope configured later.
            scopes: Vacant,
            // `iron::OAuthResponse` is not `Default`, so we choose a constructor.
            response: OAuthResponse::new,
        }
    }
}

fn consent_form(_: &mut OAuthRequest, grant: &PreGrant) -> OwnerConsent<OAuthResponse> {
    let mut response = Response::with(Status::Ok);
    response.headers.set(ContentType::html());
    response.body = Some(Box::new(support::consent_page_html("/authorize", grant)));
    OwnerConsent::InProgress(response.into())
}

fn consent_decision(request: &mut OAuthRequest, _: &PreGrant) -> OwnerConsent<OAuthResponse> {
    // Authenticate the request better in a real app!
    let allowed = request
        .0
        .url
        .as_ref()
        .query_pairs()
        .any(|(key, _)| key == "allow");
    if allowed {
        OwnerConsent::Authorized("dummy user".into())
    } else {
        OwnerConsent::Denied
    }
}
