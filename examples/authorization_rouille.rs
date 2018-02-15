mod support;

#[cfg(feature = "rouille-frontend")]
#[macro_use]
extern crate rouille;

#[cfg(feature = "rouille-frontend")]
mod main {
    extern crate oxide_auth;
    extern crate url;

    use super::rouille::{Request, Response, Server};
    use self::oxide_auth::frontends::rouille::*;

    use support::rouille::dummy_client;
    use support::open_in_browser;
    use std::sync::Mutex;
    use std::thread;

    /// Example of a main function of a iron server supporting oauth.
    pub fn example() {
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
        let bearer_tokens = Mutex::new(TokenSigner::new_from_passphrase(passphrase, None));

        let server = Server::new(("localhost", 8020), move |request| {
            use std::ops::DerefMut;

            router!(request,
                (GET) ["/"] => {
                    let mut issuer = bearer_tokens.lock().unwrap();
                    if let Err(_) = AccessFlow::new(issuer.deref_mut(),
                            &vec!["default".parse().unwrap()]
                        ).handle(request)
                    {
let text = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";
                        Response::html(text)
                    } else {
                        Response::text("Hello world!")
                    }
                },
                (GET) ["/authorize"] => {
                    let mut registrar = clients.lock().unwrap();
                    let mut authorizer = authorization_codes.lock().unwrap();
                    AuthorizationFlow::new(registrar.deref_mut(), authorizer.deref_mut())
                        .handle(request, &handle_get)
                        .unwrap_or_else(|_| Response::empty_400())
                },
                (POST) ["/authorize"] => {
                    let mut registrar = clients.lock().unwrap();
                    let mut authorizer = authorization_codes.lock().unwrap();
                    AuthorizationFlow::new(registrar.deref_mut(), authorizer.deref_mut())
                        .handle(request, &handle_post)
                        .unwrap_or_else(|_| Response::empty_400())
                },
                (POST) ["/token"] => {
                    let mut authorizer = authorization_codes.lock().unwrap();
                    let mut issuer = bearer_tokens.lock().unwrap();
                    let mut registrar = clients.lock().unwrap();
                    GrantFlow::new(registrar.deref_mut(), authorizer.deref_mut(), issuer.deref_mut())
                        .handle(request)
                        .unwrap_or_else(|_| Response::empty_400())
                },
                _ => Response::empty_404()
            )
        });

        let join = thread::spawn(move || server.unwrap().run());
        // Start a dummy client instance which simply relays the token/response
        let client = thread::spawn(|| Server::new(("localhost", 8021), dummy_client).unwrap().run());

        // Try to direct the browser to an url initiating the flow
        open_in_browser();
        join.join().expect("Failed to run");
        client.join().expect("Failed to run client");
    }

    /// A simple implementation of the first part of an authentication handler. This will
    /// display a page to the user asking for his permission to proceed. The submitted form
    /// will then trigger the other authorization handler which actually completes the flow.
    fn handle_get(_: &Request, grant: &PreGrant) -> Result<(Authentication, Response), OAuthError> {
        let text = format!(
            "<html>'{}' (at {}) is requesting permission for '{}'
            <form action=\"authorize?response_type=code&client_id={}\" method=\"post\">
                <input type=\"submit\" value=\"Accept\">
            </form>
            <form action=\"authorize?response_type=code&client_id={}&deny=1\" method=\"post\">
                <input type=\"submit\" value=\"Deny\">
            </form>
            </html>", grant.client_id, grant.redirect_uri, grant.scope, grant.client_id, grant.client_id);
        let response = Response::html(text);
        Ok((Authentication::InProgress, response))
    }

    fn handle_post(request: &Request, _: &PreGrant) -> Result<(Authentication, Response), OAuthError> {
        // No real user authentication is done here, in production you SHOULD use session keys or equivalent
        if let Some(_) = request.get_param("deny") {
            Ok((Authentication::Failed, Response::empty_400()))
        } else {
            Ok((Authentication::Authenticated("dummy user".to_string()), Response::empty_400()))
        }
    }
}

#[cfg(not(feature = "iron-frontend"))]
mod main { pub fn example() { } }

fn main() {
    main::example();
}
