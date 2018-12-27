#![feature(proc_macro_hygiene, decl_macro)]

extern crate oxide_auth;
#[macro_use]
extern crate rocket;

mod support;

use rocket::Response;

#[get("/authorize")]
fn authorize<'r>() -> Response<'r> {
    unimplemented!()
}

fn main() {
    rocket::ignite().mount("/", routes![authorize]).launch();
}
