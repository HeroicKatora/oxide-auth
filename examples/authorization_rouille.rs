#![cfg(feature = "rouille-frontend")]
mod support;

#[macro_use]
extern crate rouille;
extern crate oxide_auth;
extern crate url;

use rouille::{Request, Response, ResponseBody, Server};
use oxide_auth::code_grant::endpoint::{AuthorizationFlow, AccessTokenFlow, OwnerConsent, PreGrant, ResourceFlow};
use oxide_auth::frontends::rouille::{FnSolicitor, GenericEndpoint};

use oxide_auth::primitives::{
    authorizer::Storage,
    issuer::TokenSigner,
    registrar::{Client, ClientMap},
    generator::RandomGenerator,
    scope::Scope,
};

use support::rouille::dummy_client;
use support::open_in_browser;
use std::sync::Mutex;
use std::thread;

/// Example of a main function of a rouille server supporting oauth.
pub fn main() {
    // Stores clients in a simple in-memory hash map.
    let registrar = {
        let mut clients = ClientMap::new();
        // Register a dummy client instance
        let client = Client::public("LocalClient", // Client id
            "http://localhost:8021/endpoint".parse().unwrap(), // Redirection url
            "default".parse().unwrap()); // Allowed client scope
        clients.register_client(client);
        clients
    };

    // Authorization tokens are 16 byte random keys to a memory hash map.
    let authorizer = Storage::new(RandomGenerator::new(16));

    // Bearer tokens are signed (but not encrypted) using a passphrase.
    let issuer = TokenSigner::ephemeral();

    let endpoint = Mutex::new(GenericEndpoint {
        registrar,
        authorizer,
        issuer,
        solicitor: FnSolicitor(solicitor),
        scopes: vec!["default".parse::<Scope>().unwrap()],
        response: Response::empty_404,
    });

    // Create the main server instance
    let server = Server::new(("localhost", 8020), move |request| {
        router!(request,
            (GET) ["/"] => {
                let mut locked = endpoint.lock().unwrap();
                if let Err(err) = ResourceFlow::prepare(&mut *locked)
                    .expect("Can not fail")
                    .execute(request)
                { // Does not have the proper authorization token
                    let mut response = err.unwrap_or_else(|_| Response::empty_400());
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
                let mut locked = endpoint.lock().unwrap();
                AuthorizationFlow::prepare(&mut *locked)
                    .expect("Can not fail")
                    .execute(request)
                    .unwrap_or_else(|_| Response::empty_400())
            },
            (POST) ["/authorize"] => {
                let mut locked = endpoint.lock().unwrap();
                AuthorizationFlow::prepare(&mut *locked)
                    .expect("Can not fail")
                    .execute(request)
                    .unwrap_or_else(|_| Response::empty_400())
            },
            (POST) ["/token"] => {
                let mut locked = endpoint.lock().unwrap();
                AccessTokenFlow::prepare(&mut *locked)
                    .expect("Can not fail")
                    .execute(request)
                    .unwrap_or_else(|_| Response::empty_400())
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

/// A simple implementation of an 'owner solicitor'.
///
/// In a POST request, this will display a page to the user asking for his permission to proceed.
/// The submitted form will then trigger the other authorization handler which actually completes
/// the flow.
fn solicitor(request: &mut &Request, grant: &PreGrant) -> OwnerConsent<Response> {
    if request.method() == "GET" {
        let text = format!("<html>'{}' (at {}) is requesting permission for '{}'
<form method=\"post\">
    <input type=\"submit\" value=\"Accept\" formaction=\"authorize?response_type=code&client_id={}\">
    <input type=\"submit\" value=\"Deny\" formaction=\"authorize?response_type=code&client_id={}&deny=1\">
</form>
</html>", grant.client_id, grant.redirect_uri, grant.scope, grant.client_id, grant.client_id);
        let response = Response::html(text);
        OwnerConsent::InProgress(response)
    } else if request.method() == "POST" {
        // No real user authentication is done here, in production you MUST use session keys or equivalent
        if let Some(_) = request.get_param("deny") {
            OwnerConsent::Denied
        } else {
            OwnerConsent::Authorized("dummy user".to_string())
        }
    } else {
        unreachable!("Authorization only mounted on GET and POST")
    }
}
