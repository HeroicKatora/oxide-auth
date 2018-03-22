mod support;

extern crate gotham;
extern crate hyper;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate gotham_derive;
#[macro_use]
extern crate serde_derive;

#[cfg(feature = "gotham-frontend")]
mod main {
    extern crate oxide_auth;
    extern crate futures;
    extern crate mime;

    use self::oxide_auth::frontends::gotham::*;

    use support::gotham::dummy_client;
    use support::gotham::QueryStringExtractor;
    use support::open_in_browser;
    use std::sync::Mutex;
    use std::thread;

    use hyper::{Request, Response, StatusCode, Body};

    use gotham;
    use gotham::http::response::create_response;
    use gotham::state::{FromState, State};
    use gotham::router::builder::*;
    use gotham::pipeline::new_pipeline;
    use gotham::pipeline::single::single_pipeline;

    static PASSPHRASE: &str = "This is a super secret phrase";
lazy_static! {
    static ref REGISTRAR: Mutex<ClientMap> = {
        let mut clients  = ClientMap::new();
        // Register a dummy client instance
        let client = Client::public("LocalClient", // Client id
            "http://localhost:8021/endpoint".parse().unwrap(), // Redirection url
            "default".parse().unwrap()); // Allowed client scope
        clients.register_client(client);
        Mutex::new(clients)
    };
    static ref AUTHORIZER: Mutex<Storage<RandomGenerator>> = Mutex::new(Storage::new(RandomGenerator::new(16)));
    static ref ISSUER: Mutex<TokenSigner> = Mutex::new(TokenSigner::new_from_passphrase(&PASSPHRASE, None));
}

    #[derive(Deserialize, StateData, StaticResponseExtender)]
    pub struct OauthAuthorizeQueryStringExtractor {
        deny: Option<i32>,
    }

    pub fn example() {
        let server_router = {
            let (chain, pipelines) = single_pipeline(new_pipeline().add(OAuthRequestMiddleware).build());

            build_router(chain, pipelines, |route| {
                route.get("/").to(home_handler);

                route.get("/authorize").to(authorize_get_handler);

                route.post("/authorize").with_query_string_extractor::<OauthAuthorizeQueryStringExtractor>().to(authorize_post_handler);

                route.post("/token").to(token_handler);
            })
        };

        let client_router = {
            build_simple_router(|route| {
                route.get("/endpoint").with_query_string_extractor::<QueryStringExtractor>().to(dummy_client);
            })
        };

        // Start the server, in a real application this MUST be https instead
        let join = thread::spawn(|| gotham::start("localhost:8020", server_router));
        // Start a dummy client instance which simply relays the token/response
        let client = thread::spawn(|| gotham::start("localhost:8021", client_router));

        // Try to direct the browser to an url initiating the flow
        open_in_browser();
        join.join().expect("Failed to run");
        client.join().expect("Failed to run client");
    }

    /// A simple implementation of the first part of an authentication handler. This will
    /// display a page to the user asking for his permission to proceed. The submitted form
    /// will then trigger the other authorization handler which actually completes the flow.
    fn handle_get(_: &Request, state: &State, grant: &PreGrant) -> OwnerAuthorization<Response> {
        let text = format!(
            "<html>'{}' (at {}) is requesting permission for '{}'
            <form action=\"authorize?response_type=code&client_id={}\" method=\"post\">
                <input type=\"submit\" value=\"Accept\">
            </form>
            <form action=\"authorize?response_type=code&client_id={}&deny=1\" method=\"post\">
                <input type=\"submit\" value=\"Deny\">
            </form>
            </html>", grant.client_id, grant.redirect_uri, grant.scope, grant.client_id, grant.client_id);
        let response = create_response(
            &state,
            StatusCode::Ok,
            Some((String::from(text).into_bytes(), mime::TEXT_HTML)),
        );
        OwnerAuthorization::InProgress(response)
    }

    /// Handle form submission by a user, completing the authorization flow. The resource owner
    /// either accepted or denied the request.
    fn handle_post(_: &Request, state: &State, _: &PreGrant) -> OwnerAuthorization<Response> {
        // No real user authentication is done here, in production you SHOULD use session keys or equivalent
        let query_params = OauthAuthorizeQueryStringExtractor::borrow_from(&state);
        if let Some(_) = query_params.deny {
            OwnerAuthorization::Denied
        } else {
            OwnerAuthorization::Authorized("dummy user".to_string())
        }
    }

    fn home_handler(mut state: State) -> (State, Response) {
        let oath = state.take::<OAuthRequest>();
        let res = oath.guard()
            .and_then(|guard| {
                let mut issuer = ISSUER.lock().unwrap();
                let scopes = vec!["default".parse().unwrap()];
                let flow = AccessFlow::new(&mut *issuer, scopes.as_slice());
                guard.handle(flow)
            })
            .map(|()| {
                create_response(
                    &state,
                    StatusCode::Ok,
                    Some((String::from("Hello world!").into_bytes(), mime::TEXT_PLAIN)),
                )
            })
            .wait()
            .unwrap_or_else(|_| {
              // Does not have the proper authorization token
              let text = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";
              create_response(
                  &state,
                  StatusCode::Ok,
                  Some((String::from(text).into_bytes(), mime::TEXT_HTML)),
              )
            });

        (state, res)
    }

    fn authorize_get_handler(mut state: State) -> (State, Response) {
        let oath = state.take::<OAuthRequest>();
        let res = oath.authorization_code(&state)
            .and_then(|request| {
                let mut registrar = REGISTRAR.lock().unwrap();
                let mut authorizer = AUTHORIZER.lock().unwrap();
                let flow = AuthorizationFlow::new(&mut*registrar, &mut*authorizer);
                request.handle(flow, handle_get)
            })
            .wait()
            .unwrap_or(create_response(&state, StatusCode::BadRequest, None));

        (state, res)
    }

    fn authorize_post_handler(mut state: State) -> (State, Response) {
        let oath = state.take::<OAuthRequest>();
        let res = oath.authorization_code(&state)
            .and_then(|request| {
                let mut registrar = REGISTRAR.lock().unwrap();
                let mut authorizer = AUTHORIZER.lock().unwrap();
                let flow = AuthorizationFlow::new(&mut*registrar, &mut*authorizer);
                request.handle(flow, handle_post)
            })
            .wait()
            .unwrap_or(create_response(&state, StatusCode::BadRequest, None));

        (state, res)
    }

    fn token_handler(mut state: State) -> (State, Response) {
        let oath = state.take::<OAuthRequest>();
        let body = state.take::<Body>();
        let res = oath.access_token(body)
            .and_then(|request| {
                let mut registrar = REGISTRAR.lock().unwrap();
                let mut authorizer = AUTHORIZER.lock().unwrap();
                let mut issuer = ISSUER.lock().unwrap();
                let flow = GrantFlow::new(&mut *registrar, &mut *authorizer, &mut *issuer);
                request.handle(flow)
            })
            .wait()
            .unwrap_or(create_response(&state, StatusCode::BadRequest, None));

        (state, res)
    }
}

#[cfg(not(feature = "gotham-frontend"))]
mod main { pub fn example() { } }

fn main() {
    main::example();
}
