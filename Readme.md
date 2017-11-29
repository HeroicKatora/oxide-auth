oxide-auth
==============
A OAuth2 server library, for use in combination with iron or other frontends, featuring a set of configurable and pluggable backends.

About
--------------
`oxide-auth` aims at providing a comprehensive and extensible interface to managing oauth2 tokens on a server. While the core package is agnostic of the used frontend, an optional iron adaptor is provided with the default configuration. Through an interface designed with traits, the frontend is as easily pluggable as the backend.

Example
--------------

```rust
extern crate oxide_auth;
extern crate iron;
extern crate router;
use oxide_auth::iron::prelude::*;
use iron::prelude::*;

use std::thread;
use iron::modifier::Modifier;
use router::Router;

/// Example of a main function of a iron server supporting oauth.
pub fn main() {
    let passphrase = "This is a super secret phrase";

    // Create the main token instance, a code_granter with an iron frontend.
    let ohandler = IronGranter::new(
        // Stores clients in a simple in-memory hash map.
        ClientMap::new(),
        // Authorization tokens are 16 byte random keys to a memory hash map.
        Storage::new(RandomGenerator::new(16)),
        // Bearer tokens are signed (but not encrypted) using a passphrase.
        TokenSigner::new_from_passphrase(passphrase));

    // Register a dummy client instance
    ohandler.registrar().unwrap().register_client(
        "example",
        Url::parse("http://example.com/endpoint").unwrap());

    // Create a router and bind the relevant pages
    let mut router = Router::new();
    router.get("/authorize", ohandler.authorize(handle_get), "authorize");
    router.post("/authorize", ohandler.authorize(IronOwnerAuthorizer(handle_post)),
        "authorize");
    router.post("/token", ohandler.token(), "token");

    let mut protected = iron::Chain::new(|_: &mut Request| {
        Ok(Response::with((iron::status::Ok, "Hello World!")))
    });
    // Set up a protected resource, only accessible with a token with `default scope`.
    protected.link_before(ohandler.guard(vec!["default".parse::<Scope>().unwrap()]));
    // Instead of an error, show a warning and instructions
    protected.link_after(HelpfulAuthorizationError());
    router.get("/", protected, "protected");

    // Start the server
    // let server = thread::spawn(||
    //    iron::Iron::new(router).http("localhost:8020").unwrap());

    // server.join().expect("Failed to run");
}

/// This should display a page to the user asking for his permission to proceed.
/// You can use the Response in Ok to achieve this.
fn handle_get(_: &mut Request, auth: AuthenticationRequest) -> Result<(Authentication, Response), OAuthError> {
    unimplemented!();
}

/// This shows the second style of authentication handler, a iron::Handler compatible form.
/// Allows composition with other libraries or frameworks built around iron.
fn handle_post(req: &mut Request) -> IronResult<Response> {
    unimplemented!();
}

struct HelpfulAuthorizationError();

impl iron::middleware::AfterMiddleware for HelpfulAuthorizationError {
    fn catch(&self, _: &mut Request, err: iron::IronError) -> IronResult<Response> {
        if !err.error.is::<OAuthError>() {
           return Err(err);
        }
        let mut response = err.response;
        let text =
            "<html>
	    This page is only accessible with an oauth token, scope <em>default</em>.
            </html>";
        text.modify(&mut response);
        iron::modifiers::Header(iron::headers::ContentType::html()).modify(&mut response);
        Ok(response)
    }
}

```
