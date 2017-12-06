mod support;

#[cfg(feature = "iron-backend")]
mod main {
    extern crate oxide_auth;
    extern crate iron;
    extern crate router;
    extern crate url;
    extern crate urlencoded;

    use self::iron::prelude::*;
    use self::oxide_auth::iron::prelude::*;
    use self::urlencoded::UrlEncodedQuery;
    use support::iron::dummy_client;
    use support::open_in_browser;
    use std::collections::HashMap;
    use std::thread;

    /// Example of a main function of a iron server supporting oauth.
    pub fn example() {
        let passphrase = "This is a super secret phrase";

        // Create the main token instance, a code_granter with an iron frontend.
        let ohandler = IronGranter::new(
            // Stores clients in a simple in-memory hash map. Will only hand out `default` scopes.
            ClientMap::new(),
            // Authorization tokens are 16 byte random keys to a memory hash map.
            Storage::new(RandomGenerator::new(16)),
            // Bearer tokens are signed (but not encrypted) using a passphrase.
            TokenSigner::new_from_passphrase(passphrase));

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
        router.get("/authorize", ohandler.authorize(handle_get), "authorize");
        router.post("/authorize", ohandler.authorize(IronOwnerAuthorizer(handle_post)), "authorize");
        router.post("/token", ohandler.token(), "token");

        // Set up a protected resource, only accessible with a token with `default scope`.
        protected.link_before(ohandler.guard(vec!["default".parse().unwrap()]));
        // Instead of an error, show a warning and instructions
        protected.link_after(HelpfulAuthorizationError());
        router.get("/", protected, "protected");

        // Start the server, in a real application this MUST be https instead
        let join = thread::spawn(|| iron::Iron::new(router).http("localhost:8020").unwrap());
        // Start a dummy client instance which simply relays the token/response
        let client = thread::spawn(|| iron::Iron::new(dummy_client).http("localhost:8021").unwrap());

        // Try to direct the browser to an url initiating the flow
        open_in_browser();
        join.join().expect("Failed to run");
        client.join().expect("Failed to run client");
    }

    /// A simple implementation of the first part of an authentication handler. This will
    /// display a page to the user asking for his permission to proceed. The submitted form
    /// will then trigger the other authorization handler which actually completes the flow.
    fn handle_get(_: &mut Request, auth: &ClientParameter) -> Result<(Authentication, Response), OAuthError> {
        let text = format!(
            "<html>'{}' (at {}) is requesting permission for '{}'
            <form action=\"authorize?response_type=code&client_id={}&redirect_url=http://localhost:8021/endpoint\" method=\"post\">
                <input type=\"submit\" value=\"Accept\">
            </form>
            <form action=\"authorize?response_type=code&client_id={}&redirect_url=http://localhost:8021/endpoint&deny=1\" method=\"post\">
                <input type=\"submit\" value=\"Deny\">
            </form>
            </html>", auth.client_id, auth.redirect_url, auth.scope, auth.client_id, auth.client_id);
        let response = Response::with((iron::status::Ok, iron::modifiers::Header(iron::headers::ContentType::html()), text));
        Ok((Authentication::InProgress, response))
    }

    /// This shows the second style of authentication handler, a iron::Handler compatible form.
    /// Allows composition with other libraries or frameworks built around iron.
    fn handle_post(req: &mut Request) -> IronResult<Response> {
        // No real user authentication is done here, in production you SHOULD use session keys or equivalent
        if req.get::<UrlEncodedQuery>().unwrap_or(HashMap::new()).contains_key("deny") {
            req.extensions.insert::<Authentication>(Authentication::Failed);
        } else {
            req.extensions.insert::<Authentication>(Authentication::Authenticated("dummy user".to_string()));
        }
        Ok(Response::with(iron::status::Ok))
    }

    struct HelpfulAuthorizationError();

    impl iron::middleware::AfterMiddleware for HelpfulAuthorizationError {
        fn catch(&self, _: &mut Request, err: iron::IronError) -> IronResult<Response> {
            if !err.error.is::<OAuthError>() {
                return Err(err);
            }
            use main::iron::modifier::Modifier;
            let mut response = err.response;
            let text =
                "<html>
                This page should be accessed via an oauth token from the client in the example. Click
                <a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient&redirect_url=http://localhost:8021/endpoint\">
                here</a> to begin the authorization process.
                </html>";
            text.modify(&mut response);
            iron::modifiers::Header(iron::headers::ContentType::html()).modify(&mut response);
            Ok(response)
        }
    }
}

#[cfg(not(feature = "iron-backend"))]
mod main { pub fn example() { } }

fn main() {
    main::example();
}
