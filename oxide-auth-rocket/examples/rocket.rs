#![feature(proc_macro_hygiene, decl_macro)]

extern crate oxide_auth;
extern crate oxide_auth_rocket;
#[macro_use]
extern crate rocket;

#[rustfmt::skip]
#[path = "../../examples/support/rocket.rs"]
mod support;

use std::io;
use std::sync::Mutex;

use oxide_auth::endpoint::{OwnerConsent, Solicitation};
use oxide_auth::frontends::simple::endpoint::{FnSolicitor, Generic, Vacant};
use oxide_auth::primitives::prelude::*;
use oxide_auth::primitives::registrar::RegisteredUrl;
use oxide_auth_rocket::{OAuthResponse, OAuthRequest, OAuthFailure};

use rocket::{Data, State, Response, http};
use rocket::http::ContentType;
use rocket::response::Responder;

struct MyState {
    registrar: Mutex<ClientMap>,
    authorizer: Mutex<AuthMap<RandomGenerator>>,
    issuer: Mutex<TokenMap<RandomGenerator>>,
}

#[get("/authorize")]
fn authorize<'r>(
    oauth: OAuthRequest<'r>, state: State<MyState>,
) -> Result<OAuthResponse<'r>, OAuthFailure> {
    state
        .endpoint()
        .with_solicitor(FnSolicitor(consent_form))
        .authorization_flow()
        .execute(oauth)
        .map_err(|err| err.pack::<OAuthFailure>())
}

#[post("/authorize?<allow>")]
fn authorize_consent<'r>(
    oauth: OAuthRequest<'r>, allow: Option<bool>, state: State<MyState>,
) -> Result<OAuthResponse<'r>, OAuthFailure> {
    let allowed = allow.unwrap_or(false);
    state
        .endpoint()
        .with_solicitor(FnSolicitor(move |_: &mut _, grant: Solicitation<'_>| {
            consent_decision(allowed, grant)
        }))
        .authorization_flow()
        .execute(oauth)
        .map_err(|err| err.pack::<OAuthFailure>())
}

#[post("/token", data = "<body>")]
fn token<'r>(
    mut oauth: OAuthRequest<'r>, body: Data, state: State<MyState>,
) -> Result<OAuthResponse<'r>, OAuthFailure> {
    oauth.add_body(body);
    state
        .endpoint()
        .access_token_flow()
        .execute(oauth)
        .map_err(|err| err.pack::<OAuthFailure>())
}

#[post("/refresh", data = "<body>")]
fn refresh<'r>(
    mut oauth: OAuthRequest<'r>, body: Data, state: State<MyState>,
) -> Result<OAuthResponse<'r>, OAuthFailure> {
    oauth.add_body(body);
    state
        .endpoint()
        .refresh_flow()
        .execute(oauth)
        .map_err(|err| err.pack::<OAuthFailure>())
}

#[get("/")]
fn protected_resource<'r>(oauth: OAuthRequest<'r>, state: State<MyState>) -> impl Responder<'r> {
    const DENY_TEXT: &str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

    let protect = state
        .endpoint()
        .with_scopes(vec!["default-scope".parse().unwrap()])
        .resource_flow()
        .execute(oauth);
    match protect {
        Ok(_grant) => Ok("Hello, world"),
        Err(Ok(response)) => {
            let error: OAuthResponse = Response::build_from(response.into())
                .header(ContentType::HTML)
                .sized_body(io::Cursor::new(DENY_TEXT))
                .finalize()
                .into();
            Err(Ok(error))
        }
        Err(Err(err)) => Err(Err(err.pack::<OAuthFailure>())),
    }
}

fn main() {
    rocket::ignite()
        .mount(
            "/",
            routes![authorize, authorize_consent, token, protected_resource, refresh,],
        )
        // We only attach the test client here because there can only be one rocket.
        .attach(support::ClientFairing)
        .manage(MyState::preconfigured())
        .launch();
}

impl MyState {
    pub fn preconfigured() -> Self {
        MyState {
            registrar: Mutex::new(
                vec![Client::public(
                    "LocalClient",
                    RegisteredUrl::Semantic(
                        "http://localhost:8000/clientside/endpoint".parse().unwrap(),
                    ),
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

fn consent_form<'r>(
    _: &mut OAuthRequest<'r>, solicitation: Solicitation,
) -> OwnerConsent<OAuthResponse<'r>> {
    OwnerConsent::InProgress(
        Response::build()
            .status(http::Status::Ok)
            .header(http::ContentType::HTML)
            .sized_body(io::Cursor::new(support::consent_page_html(
                "/authorize",
                solicitation,
            )))
            .finalize()
            .into(),
    )
}

fn consent_decision<'r>(allowed: bool, _: Solicitation) -> OwnerConsent<OAuthResponse<'r>> {
    if allowed {
        OwnerConsent::Authorized("dummy user".into())
    } else {
        OwnerConsent::Denied
    }
}
