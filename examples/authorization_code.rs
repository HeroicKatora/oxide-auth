#![cfg(feature = "iron-frontend")]
mod support;

extern crate oxide_auth;
extern crate iron;
extern crate router;
extern crate url;
extern crate urlencoded;

use iron::prelude::*;
use oxide_auth::frontends::iron::prelude::*;
use urlencoded::UrlEncodedQuery;
use support::iron::dummy_client;
use support::open_in_browser;
use std::collections::HashMap;
use std::thread;

/// Example of a main function of a iron server supporting oauth.
pub fn main() {
    // Create the main token instance, a code_granter with an iron frontend.
    let ohandler = IronGranter::new(
        // Stores clients in a simple in-memory hash map.
        ClientMap::new(),
        // Authorization tokens are 16 byte random keys to a memory hash map.
        Storage::new(RandomGenerator::new(16)),
        // Bearer tokens are signed (but not encrypted) using a passphrase.
        TokenSigner::ephemeral());

    // Register a dummy client instance
    let client = Client::public("LocalClient", // Client id
        "http://localhost:8021/endpoint".parse().unwrap(), // Redirection url
        "default".parse().unwrap()); // Allowed client scope
    ohandler.registrar().unwrap().register_client(client);

    // Create a router and bind the relevant pages
    let mut router = router::Router::new();
    let mut protected = iron::Chain::new(|_: &mut Request| {
        Ok(Response::with((iron::status::Ok, "Hello World!")))
    });

    // Set up required oauth endpoints
    router.get("/authorize", ohandler.authorize(MethodAuthorizer(handle_get)), "authorize");
    router.post("/authorize", ohandler.authorize(IronOwnerAuthorizer(handle_post)), "authorize");
    router.post("/token", ohandler.token(), "token");

    // Set up a protected resource, only accessible with a token with `default scope`.
    protected.link_before(ohandler.guard(vec!["default".parse().unwrap()]));
    // Instead of an error, show a warning and instructions
    protected.link_after(HelpfulAuthorizationError());
    router.get("/", protected, "protected");

    // Start the server, in a real application this MUST be https instead
    let join = thread::spawn(|| iron::Iron::new(router).http(("localhost", 8020)).unwrap());
    // Start a dummy client instance which simply relays the token/response
    let client = thread::spawn(|| iron::Iron::new(dummy_client).http(("localhost", 8021)).unwrap());

    // Try to direct the browser to an url initiating the flow
    open_in_browser();
    join.join().expect("Failed to run");
    client.join().expect("Failed to run client");
}

/// A simple implementation of the first part of an authentication handler. This will
/// display a page to the user asking for his permission to proceed. The submitted form
/// will then trigger the other authorization handler which actually completes the flow.
fn handle_get(_: &mut Request, grant: &PreGrant) -> OwnerAuthorization<Response> {
    let text = format!(
        "<html>'{}' (at {}) is requesting permission for '{}'
        <form method=\"post\">
            <input type=\"submit\" value=\"Accept\" formaction=\"authorize?response_type=code&client_id={}\">
            <input type=\"submit\" value=\"Deny\" formaction=\"authorize?response_type=code&client_id={}&deny=1\">
        </form>
        </html>", grant.client_id, grant.redirect_uri, grant.scope, grant.client_id, grant.client_id);
    let response = Response::with((iron::status::Ok, iron::modifiers::Header(iron::headers::ContentType::html()), text));
    OwnerAuthorization::InProgress(response)
}

/// This shows the second style of authentication handler, a iron::Handler compatible form.
/// Allows composition with other libraries or frameworks built around iron.
fn handle_post(req: &mut Request) -> IronResult<Response> {
    // No real user authentication is done here, in production you SHOULD use session keys or equivalent
    let mut response = Response::with(iron::status::Ok);
    if req.get::<UrlEncodedQuery>().unwrap_or(HashMap::new()).contains_key("deny") {
        response.extensions.insert::<SimpleAuthorization>(SimpleAuthorization::Denied);
    } else {
        response.extensions.insert::<SimpleAuthorization>(SimpleAuthorization::Allowed("dummy user".to_string()));
    }
    Ok(response)
}

/// Show a message to unauthorized requests of the protected resource.
struct HelpfulAuthorizationError();

impl iron::middleware::AfterMiddleware for HelpfulAuthorizationError {
    fn catch(&self, _: &mut Request, err: iron::IronError) -> IronResult<Response> {
        use iron::modifier::Modifier;

        let IronError { error, response } = err;
        let oauth_error = match error.downcast::<OAuthError>() {
            Ok(boxed_err) => boxed_err,
            Err(error) => return Err(IronError { error, response }),
        };

        let mut response = oauth_error.response_or_else(||
            Response::with(iron::status::InternalServerError));

        let text =
            "<html>
            This page should be accessed via an oauth token from the client in the example. Click
            <a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
            here</a> to begin the authorization process.
            </html>";
        text.modify(&mut response);
        iron::modifiers::Header(iron::headers::ContentType::html()).modify(&mut response);
        Ok(response)
    }
}
