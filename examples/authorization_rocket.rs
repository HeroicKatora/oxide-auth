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
use rocket::http::ContentType;
use rocket::response::Responder;

use support::{consent_page_html, rocket as support_rocket};

struct MyState {
    registrar: Mutex<ClientMap>,
    authorizer: Mutex<Storage<RandomGenerator>>,
    issuer: Mutex<TokenSigner>,
}

#[get("/authorize")]
fn authorize<'r>(oauth: OAuthRequest<'r>, state: State<MyState>) -> Result<Response<'r>, OAuthFailure> {
    state.endpoint()
        .with_solicitor(FnSolicitor(consent_form))
        .to_authorization()
        .execute(oauth)
        .map_err(|err| err.pack::<OAuthFailure>())
}

#[post("/authorize?<allow>")]
fn authorize_consent<'r>(oauth: OAuthRequest<'r>, allow: Option<bool>, state: State<MyState>)
    -> Result<Response<'r> , OAuthFailure>
{
    let allowed = allow.unwrap_or(false);
    state.endpoint()
        .with_solicitor(FnSolicitor(move |_: &mut _, grant: &_| consent_post(allowed, grant)))
        .to_authorization()
        .execute(oauth)
        .map_err(|err| err.pack::<OAuthFailure>())
}

#[post("/token", data="<body>")]
fn token<'r>(mut oauth: OAuthRequest<'r>, body: Data, state: State<MyState>)
    -> Result<Response<'r>, OAuthFailure>
{
    oauth.add_body(body);
    state.endpoint()
        .to_access_token()
        .execute(oauth)
        .map_err(|err| err.pack::<OAuthFailure>())
}

#[get("/")]
fn protected_resource<'r>(oauth: OAuthRequest<'r>, state: State<MyState>)
    -> impl Responder<'r>
{
    const DENY_TEXT: &str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

    let protect = state.endpoint()
        .to_resource()
        .execute(oauth);
    match protect {
        Ok(()) => Ok("Hello, world"),
        Err(Ok(response)) => {
            let error = Response::build_from(response)
                .header(ContentType::HTML)
                .sized_body(io::Cursor::new(DENY_TEXT))
                .finalize();
            Err(Ok(error))
        },
        Err(Err(err)) => Err(Err(err.pack::<OAuthFailure>())),
    }
}

fn main() {
    rocket::ignite()
        .mount("/", routes![
            authorize,
            authorize_consent,
            token,
            protected_resource
        ])
        .attach(support_rocket::ClientFairing)
        .manage(MyState::preconfigured())
        .launch();
}

impl MyState {
    pub fn preconfigured() -> Self {
        MyState {
            registrar: Mutex::new(vec![
                Client::public("LocalClient",
                    "http://localhost:8000/clientside/endpoint".parse().unwrap(),
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

fn consent_form<'r>(_: &mut OAuthRequest<'r>, grant: &PreGrant) -> OwnerConsent<Response<'r>> {
    OwnerConsent::InProgress(Response::build()
        .status(http::Status::Ok)
        .header(http::ContentType::HTML)
        .sized_body(io::Cursor::new(consent_page_html("/authorize", grant)))
        .finalize())
}

fn consent_post<'r>(allowed: bool, _: &PreGrant) -> OwnerConsent<Response<'r>> {
    if allowed { 
        OwnerConsent::Authorized("dummy user".into()) 
    } else {
        OwnerConsent::Denied 
    }
}
