#![cfg(feature = "rouille-frontend")]
mod support;

#[macro_use]
extern crate rouille;
extern crate oxide_auth;
extern crate url;

use rouille::{Request, Response, ResponseBody, Server};
use oxide_auth::frontends::rouille::*;

use support::rouille::dummy_client;
use support::open_in_browser;
use std::sync::{Arc, Mutex};
use std::thread;

/// Example of a main function of a rouille server supporting oauth.
pub fn main() {
    // Stores clients in a simple in-memory hash map.
    let clients =  {
        let mut clients = ClientMap::new();
        // Register a dummy client instance
        let client = Client::public("LocalClient", // Client id
            "http://localhost:8021/endpoint".parse().unwrap(), // Redirection url
            "default".parse().unwrap()); // Allowed client scope
        clients.register_client(client);
        Mutex::new(clients)
    };

    // Authorization tokens are 16 byte random keys to a memory hash map.
    let authorization_codes = Mutex::new(Storage::new(RandomGenerator::new(16)));

    // Bearer tokens are signed (but not encrypted) using a passphrase.
    let passphrase = "This is a super secret phrase";
    let bearer_tokens = Arc::new(TokenSigner::new_from_passphrase(passphrase, None));

    // Create the main server instance
    let server = Server::new(("localhost", 8020), move |request| {
        router!(request,
            (GET) ["/"] => {
                let mut issuer = &*bearer_tokens;
                if let Err(err) = AccessFlow::new(&mut issuer, &vec!["default".parse().unwrap()])
                    .handle(request)
                { // Does not have the proper authorization token
                    let mut response = err.response_or_else(Response::empty_404);
let text = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";
                    response.data = ResponseBody::from_string(text);
                    response.with_unique_header("Content-Type", "text/html; charset=utf8")
                } else { // Allowed to access!
                    Response::text("Hello world!")
                }
            },
            (GET) ["/authorize"] => {
                let mut registrar = clients.lock().unwrap();
                let mut authorizer = authorization_codes.lock().unwrap();
                AuthorizationFlow::new(&mut*registrar, &mut*authorizer)
                    .handle(request).complete(&handle_get)
                    .unwrap_or_else(|err| err.response_or_else(Response::empty_404))
            },
            (POST) ["/authorize"] => {
                let mut registrar = clients.lock().unwrap();
                let mut authorizer = authorization_codes.lock().unwrap();
                AuthorizationFlow::new(&mut*registrar, &mut*authorizer)
                    .handle(request).complete(&handle_post)
                    .unwrap_or_else(|err| err.response_or_else(Response::empty_404))
            },
            (POST) ["/token"] => {
                let mut authorizer = authorization_codes.lock().unwrap();
                let mut issuer = &*bearer_tokens;
                let mut registrar = clients.lock().unwrap();
                GrantFlow::new(&mut*registrar, &mut*authorizer, &mut issuer)
                    .handle(request)
                    .unwrap_or_else(|err| err.response_or_else(Response::empty_404))
            },
            _ => Response::empty_404()
        )
    });

    // Run the server main loop in another thread
    let join = thread::spawn(move ||
        server.expect("Failed to start server")
            .run()
    );
    // Start a dummy client instance which simply relays the token/response
    let client = thread::spawn(||
        Server::new(("localhost", 8021), dummy_client)
            .expect("Failed to start client")
            .run()
    );

    // Try to direct the browser to an url initiating the flow
    open_in_browser();
    join.join().expect("Failed to run");
    client.join().expect("Failed to run client");
}

/// A simple implementation of the first part of an authentication handler. This will
/// display a page to the user asking for his permission to proceed. The submitted form
/// will then trigger the other authorization handler which actually completes the flow.
fn handle_get(_: &Request, grant: &PreGrant) -> OwnerAuthorization<Response> {
    let text = format!(
        "<html>'{}' (at {}) is requesting permission for '{}'
        <form method=\"post\">
            <input type=\"submit\" value=\"Accept\" formaction=\"authorize?response_type=code&client_id={}\">
            <input type=\"submit\" value=\"Deny\" formaction=\"authorize?response_type=code&client_id={}&deny=1\">
        </form>
        </html>", grant.client_id, grant.redirect_uri, grant.scope, grant.client_id, grant.client_id);
    let response = Response::html(text);
    OwnerAuthorization::InProgress(response)
}

/// Handle form submission by a user, completing the authorization flow. The resource owner
/// either accepted or denied the request.
fn handle_post(request: &Request, _: &PreGrant) -> OwnerAuthorization<Response> {
    // No real user authentication is done here, in production you SHOULD use session keys or equivalent
    if let Some(_) = request.get_param("deny") {
        OwnerAuthorization::Denied
    } else {
        OwnerAuthorization::Authorized("dummy user".to_string())
    }
}
