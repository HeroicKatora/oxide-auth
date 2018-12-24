#![cfg(feature = "disabled")]
mod support;
#[cfg(feature = "gotham-frontend")]
mod support_gotham;

#[cfg(feature = "gotham-frontend")]
extern crate gotham;
#[cfg(feature = "gotham-frontend")]
extern crate hyper;
#[cfg(feature = "gotham-frontend")]
#[macro_use]
extern crate gotham_derive;
#[cfg(feature = "gotham-frontend")]
#[macro_use]
extern crate serde_derive;

#[cfg(feature = "gotham-frontend")]
mod main {
    extern crate oxide_auth;
    extern crate futures;
    extern crate mime;
    extern crate serde_urlencoded;

    use self::oxide_auth::frontends::gotham::*;

    use support_gotham::dummy_client;
    use support::open_in_browser;
    use std::collections::HashMap;
    use std::thread;

    use hyper::{Request, Response, StatusCode, Body};
    use hyper::header::{ContentLength, ContentType};

    use gotham;
    use gotham::handler::HandlerFuture;
    use gotham::http::response::create_response;
    use gotham::middleware::Middleware;
    use gotham::state::State;
    use gotham::router::builder::*;
    use gotham::pipeline::new_pipeline;
    use gotham::pipeline::set::{finalize_pipeline_set, new_pipeline_set};

    #[derive(Deserialize, StateData, StaticResponseExtender)]
    pub struct OauthResultQueryExtractor {
        pub error: Option<String>,
        pub code: Option<String>,
    }

    pub fn example() {
        let mut clients = ClientMap::new();
        // Register a dummy client instance
        let client = Client::public(
            "LocalClient", // Client id
            "http://localhost:8021/endpoint".parse().unwrap(), // Redirection url
            "default".parse().unwrap() // Allowed client scope
        );
        clients.register_client(client);

        // Create the gotham provider.
        let ohandler = GothamOauthProvider::new(
            // Stores clients in a simple in-memory hash map.
            clients,
            // Authorization tokens are 16 byte random keys to a memory hash map.
            Storage::new(RandomGenerator::new(16)),
            // Bearer tokens are signed (but not encrypted) using a passphrase.
            TokenSigner::ephemeral(),
        );

        /// Middleware that will show a helpful message to unauthorized requests
        /// of the protected resource.
        #[derive(Clone, NewMiddleware)]
        pub struct OAuthErrorMiddleware;

        impl Middleware for OAuthErrorMiddleware {
            fn call<Chain>(self, state: State, chain: Chain) -> Box<HandlerFuture>
            where
                Chain: FnOnce(State) -> Box<HandlerFuture> + 'static,
            {
                let result = chain(state);
                let f = result.or_else(move |(state, _error)| {
                    let text = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>";

                    let response = create_response(
                        &state,
                        StatusCode::Ok,
                        Some((String::from(text).into_bytes(), mime::TEXT_HTML)),
                    );

                    future::ok((state, response))
                });


                Box::new(f)
            }
        }

        let scopes = vec!["default".parse().unwrap()];

        let server_router = {
            let pipelines = new_pipeline_set();
            let (pipelines, default) = pipelines.add(
                new_pipeline()
                    .add(OAuthStateDataMiddleware::new(ohandler))
                    .build()
            );
            let (pipelines, extended) = pipelines.add(
                new_pipeline()
                    .add(OAuthErrorMiddleware)
                    .add(OAuthGuardMiddleware::new(scopes))
                    .build()
            );
            let pipeline_set = finalize_pipeline_set(pipelines);

            let default_chain = (default, ());
            let oauth_guarded_chain = (extended, default_chain);
            build_router(default_chain, pipeline_set, |route| {
                route.with_pipeline_chain(oauth_guarded_chain, |route| {
                    route.get("/").to(home_handler);
                });

                route.associate("/authorize", |route| {
                    route.get().to(authorize_get_handler);
                    route.post().to(authorize_post_handler);
                });

                route.post("/token").to(token_handler);
            })
        };

        let client_router = {
            build_simple_router(|route| {
                route.get("/endpoint")
                    .with_query_string_extractor::<OauthResultQueryExtractor>()
                    .to(dummy_client);
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
    fn handle_get(_: &Request, grant: &PreGrant) -> OwnerAuthorization<Response> {
        let text = format!(
            "<html>'{}' (at {}) is requesting permission for '{}'
            <form action=\"authorize?response_type=code&client_id={}\" method=\"post\">
                <input type=\"submit\" value=\"Accept\">
            </form>
            <form action=\"authorize?response_type=code&client_id={}&deny=1\" method=\"post\">
                <input type=\"submit\" value=\"Deny\">
            </form>
            </html>", grant.client_id, grant.redirect_uri, grant.scope, grant.client_id, grant.client_id);
        let response = Response::new()
            .with_header(ContentLength(text.len() as u64))
            .with_header(ContentType(mime::TEXT_HTML))
            .with_status(StatusCode::Ok)
            .with_body(text.to_owned());
        OwnerAuthorization::InProgress(response)
    }

    /// Handle form submission by a user, completing the authorization flow. The resource owner
    /// either accepted or denied the request.
    fn handle_post(request: &Request, _: &PreGrant) -> OwnerAuthorization<Response> {
        // No real user authentication is done here, in production you SHOULD use session keys or equivalent
        let query = request.query().and_then(|query_string| {
            serde_urlencoded::from_str::<HashMap<String, String>>(query_string).ok()
        }).unwrap_or(HashMap::new());
        if query.contains_key("deny") {
            OwnerAuthorization::Denied
        } else {
            OwnerAuthorization::Authorized("dummy user".to_string())
        }
    }

    fn home_handler(state: State) -> (State, Response) {
        let res = create_response(
            &state,
            StatusCode::Ok,
            Some((String::from("Hello world!").into_bytes(), mime::TEXT_PLAIN)),
        );

        (state, res)
    }

    fn authorize_get_handler(state: State) -> Box<HandlerFuture> {
        let oauth = state.borrow::<GothamOauthProvider>().clone();
        let f = oauth.authorization_code_request(&state).then(|result| {
            match result {
                Ok(request) => {
                    let oauth = state.borrow::<GothamOauthProvider>().clone();
                    let mut registrar = oauth.registrar().unwrap();
                    let mut authorizer = oauth.authorizer().unwrap();
                    let flow = AuthorizationFlow::new(&mut *registrar, &mut *authorizer);
                    future::ok((state, request.handle(flow, handle_get).unwrap()))
                },
                Err(_) => {
                    let res = create_response(&state, StatusCode::BadRequest, None);
                    future::ok((state, res))
                }
            }
        });

        Box::new(f)
    }

    fn authorize_post_handler(state: State) -> Box<HandlerFuture> {
        let oauth = state.borrow::<GothamOauthProvider>().clone();
        let f = oauth.authorization_code_request(&state).then(|result| {
            match result {
                Ok(request) => {
                    let oauth = state.borrow::<GothamOauthProvider>().clone();
                    let mut registrar = oauth.registrar().unwrap();
                    let mut authorizer = oauth.authorizer().unwrap();
                    let flow = AuthorizationFlow::new(&mut *registrar, &mut *authorizer);
                    future::ok((state, request.handle(flow, handle_post).unwrap()))
                },
                Err(_) => {
                    let res = create_response(&state, StatusCode::BadRequest, None);
                    future::ok((state, res))
                }
            }
        });

        Box::new(f)
    }

    fn token_handler(mut state: State) -> Box<HandlerFuture> {
        let oauth = state.borrow::<GothamOauthProvider>().clone();
        let body = state.take::<Body>();
        let f = oauth.access_token_request(&state, body).then(|result| {
            match result {
                Ok(request) => {
                    let oauth = state.borrow::<GothamOauthProvider>().clone();
                    let mut registrar = oauth.registrar().unwrap();
                    let mut authorizer = oauth.authorizer().unwrap();
                    let mut issuer = oauth.issuer().unwrap();
                    let flow = GrantFlow::new(&mut *registrar, &mut *authorizer, &mut *issuer);
                    future::ok((state, request.handle(flow).unwrap()))
                },
                Err(_) => {
                    let res = create_response(&state, StatusCode::BadRequest, None);
                    future::ok((state, res))
                }
            }
        });

        Box::new(f)
    }
}

#[cfg(not(feature = "gotham-frontend"))]
mod main { pub fn example() { } }

fn main() {
    main::example();
}
