#[macro_use]
extern crate rouille;

#[rustfmt::skip]
#[path = "../../examples/support/rouille.rs"]
mod support;

use std::sync::Mutex;
use std::thread;

use oxide_auth::endpoint::{
    AuthorizationFlow, AccessTokenFlow, OwnerConsent, RefreshFlow, ResourceFlow, Solicitation,
};
use oxide_auth::primitives::prelude::*;
use oxide_auth_rouille::{Request, Response as OAuthResponse};
use oxide_auth_rouille::{FnSolicitor, GenericEndpoint};
use rouille::{Response, ResponseBody, Server};

/// Example of a main function of a rouille server supporting oauth.
pub fn main() {
    // Stores clients in a simple in-memory hash map.
    let registrar = {
        let mut clients = ClientMap::new();
        // Register a dummy client instance
        let client = Client::public(
            "LocalClient", // Client id
            "http://localhost:8021/endpoint"
                .parse::<url::Url>()
                .unwrap()
                .into(), // Redirection url
            "default".parse().unwrap(),
        ); // Allowed client scope
        clients.register_client(client);
        clients
    };

    // Authorization tokens are 16 byte random keys to a memory hash map.
    let authorizer = AuthMap::new(RandomGenerator::new(16));

    // Bearer tokens are also random generated but 256-bit tokens, since they live longer and this
    // example is somewhat paranoid.
    //
    // We could also use a `TokenSigner::ephemeral` here to create signed tokens which can be read
    // and parsed by anyone, but not maliciously created. However, they can not be revoked and thus
    // don't offer even longer lived refresh tokens.
    let issuer = TokenMap::new(RandomGenerator::new(32));

    let endpoint = Mutex::new(GenericEndpoint {
        registrar,
        authorizer,
        issuer,
        solicitor: FnSolicitor(solicitor),
        scopes: vec!["default".parse::<Scope>().unwrap()],
        response: || OAuthResponse::from(Response::empty_404()),
    });

    // Create the main server instance
    let server = Server::new(("localhost", 8020), move |request| {
        router!(request,
                    (GET) ["/"] => {
                        let mut locked = endpoint.lock().unwrap();
                        if let Err(err) = ResourceFlow::prepare(&mut *locked)
                            .expect("Can not fail")
                            .execute(Request::new(request))
                        { // Does not have the proper authorization token
                            let mut response = err
                                .map(OAuthResponse::into_inner)
                                .unwrap_or_else(|_| Response::empty_400());
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
                            .execute(Request::new(request))
                            .map(OAuthResponse::into_inner)
                            .unwrap_or_else(|_| Response::empty_400())
                    },
                    (POST) ["/authorize"] => {
                        let mut locked = endpoint.lock().unwrap();
                        AuthorizationFlow::prepare(&mut *locked)
                            .expect("Can not fail")
                            .execute(Request::new(request))
                            .map(OAuthResponse::into_inner)
                            .unwrap_or_else(|_| Response::empty_400())
                    },
                    (POST) ["/token"] => {
                        let mut locked = endpoint.lock().unwrap();
                        AccessTokenFlow::prepare(&mut *locked)
                            .expect("Can not fail")
                            .execute(Request::new(request))
                            .map(OAuthResponse::into_inner)
                            .unwrap_or_else(|_| Response::empty_400())
                    },
                    (POST) ["/refresh"] => {
                        let mut locked = endpoint.lock().unwrap();
                        RefreshFlow::prepare(&mut *locked)
                            .expect("Can not fail")
                            .execute(Request::new(request))
                            .map(OAuthResponse::into_inner)
                            .unwrap_or_else(|_| Response::empty_400())
                    },
                    _ => Response::empty_404()
                )
    });

    // Run the server main loop in another thread
    let join = thread::spawn(move || server.expect("Failed to start server").run());
    // Start a dummy client instance which simply relays the token/response
    let client = thread::spawn(|| {
        Server::new(("localhost", 8021), support::dummy_client())
            .expect("Failed to start client")
            .run()
    });

    // Try to direct the browser to an url initiating the flow
    support::open_in_browser(8020);
    join.join().expect("Failed to run");
    client.join().expect("Failed to run client");
}

/// A simple implementation of an 'owner solicitor'.
///
/// In a POST request, this will display a page to the user asking for his permission to proceed.
/// The submitted form will then trigger the other authorization handler which actually completes
/// the flow.
fn solicitor(request: &mut Request, grant: Solicitation<'_>) -> OwnerConsent<OAuthResponse> {
    if request.method() == "GET" {
        let text = support::consent_page_html("/authorize".into(), grant);
        let response = Response::html(text);
        OwnerConsent::InProgress(response.into())
    } else if request.method() == "POST" {
        // No real user authentication is done here, in production you MUST use session keys or equivalent
        if let Some(_) = request.get_param("allow") {
            OwnerConsent::Authorized("dummy user".to_string())
        } else {
            OwnerConsent::Denied
        }
    } else {
        unreachable!("Authorization only mounted on GET and POST")
    }
}
