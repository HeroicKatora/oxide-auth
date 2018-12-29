#![feature(proc_macro_hygiene, decl_macro)]

extern crate oxide_auth;
#[macro_use]
extern crate rocket;

mod support;

use std::io;
use std::sync::Mutex;

use oxide_auth::code_grant::endpoint::{AuthorizationFlow};
use oxide_auth::code_grant::endpoint::{Endpoint, OAuthError, OwnerConsent, PreGrant};
use oxide_auth::frontends::simple::endpoint::{FnSolicitor, Generic, Vacant};
use oxide_auth::frontends::rocket::{OAuthRequest, OAuthFailure};
use oxide_auth::primitives::prelude::*;

use rocket::{Data, State, Response, http};

use support::consent_page_html;

struct MyState {
    registrar: Mutex<ClientMap>,
    authorizer: Mutex<Storage<RandomGenerator>>,
    issuer: Mutex<TokenSigner>,
}

#[get("/authorize")]
fn authorize<'r>(oauth: OAuthRequest<'r>, state: State<MyState>) -> Result<Response<'r>, OAuthFailure> {
    state.endpoint()
        .with_solicitor(FnSolicitor(solicit_get))
        .as_authorization()
        .execute(oauth)
        .map_err(|err| err.pack::<OAuthFailure>())
}

#[post("/authorize?<deny>")]
fn authorize_consent<'r>(oauth: OAuthRequest<'r>, deny: Option<bool>) -> Response<'r> {
    let consent = deny.unwrap_or(true);
    unimplemented!()
}

#[post("/token", data="<body>")]
fn token<'r>(mut oauth: OAuthRequest<'r>, body: Data) -> Response<'r> {
    oauth.add_body(body);
    unimplemented!()
}

#[get("/")]
fn protected_resource(nah: OAuthRequest) -> &'static str {
    unimplemented!()
}

fn main() {
    rocket::ignite()
        .mount("/", routes![
            authorize,
            authorize_consent,
            token,
            protected_resource
        ])
        .manage(MyState::preconfigured())
        .launch();
}

impl MyState {
    pub fn preconfigured() -> Self {
        MyState {
            registrar: Mutex::new(vec![
                Client::public("LocalClient",
                    "http://localhost:8021/endpoint".parse().unwrap(),
                    "default-scope".parse().unwrap())
            ].into_iter().collect()),
            authorizer: Mutex::new(Storage::new(RandomGenerator::new(16))),
            issuer: Mutex::new(TokenSigner::ephemeral()),
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

fn solicit_get<'r>(oauth: &mut OAuthRequest<'r>, grant: &PreGrant) -> OwnerConsent<Response<'r>> {
    OwnerConsent::InProgress(Response::build()
        .status(http::Status::Ok)
        .header(http::ContentType::HTML)
        .sized_body(io::Cursor::new(consent_page_html("/authorize", grant)))
        .finalize())
}
