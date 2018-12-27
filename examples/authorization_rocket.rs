#![feature(proc_macro_hygiene, decl_macro)]

extern crate oxide_auth;
#[macro_use]
extern crate rocket;

mod support;

use oxide_auth::frontends::rocket::OAuthRequest;
use rocket::{Data, Response};

#[get("/authorize")]
fn authorize<'r>(oauth: OAuthRequest<'r>) -> Response<'r> {
    unimplemented!()
}

#[post("/authorize?<deny>")]
fn authorize_consent<'r>(oauth: OAuthRequest<'r>, deny: Option<bool>) -> Response<'r> {
    unimplemented!()
}

#[post("/token", data="<body>")]
fn token<'r>(oauth: OAuthRequest<'r>, body: Data) -> Response<'r> {
    unimplemented!()
}

#[get("/")]
fn protected_resource(nah: OAuthRequest) -> &'static str {
    unimplemented!()
}

fn main() {
    rocket::ignite().mount("/", routes![
        authorize,
        authorize_consent,
        token,
        protected_resource
    ]).launch();
}
