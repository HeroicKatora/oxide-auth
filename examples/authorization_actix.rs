mod support;
#[macro_use]
extern crate lazy_static;

#[cfg(feature = "actix-frontend")]
mod main {
    extern crate actix;
    extern crate actix_web;
    extern crate oxide_auth;
    extern crate url;

    use super::support::actix::dummy_client;
    use self::actix_web::*;
    use self::oxide_auth::frontends::actix::*;

    use std::sync::Mutex;

    type State = ();

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
    /// Example of a main function of a rouille server supporting oauth.
    pub fn example() {
        let sys = actix::System::new("HttpServer");

        // Create the main server instance
        HttpServer::new(
            || Application::with_state(())
                .handler("/authorize", |req: HttpRequest<State>| {
                    match *req.method() {
                        Method::GET => req.oauth2().authorization_code()
                            .and_then(|request| {
                                let mut registrar = REGISTRAR.lock().unwrap();
                                let mut authorizer = AUTHORIZER.lock().unwrap();
                                let flow = AuthorizationFlow::new(&mut *registrar, &mut *authorizer);
                                request.handle(flow, handle_get)
                            })
                            .wait()
                            .unwrap_or(httpcodes::HTTPBadRequest.with_body(Body::Empty)),
                        Method::POST => req.oauth2().authorization_code()
                            .and_then(|request| {
                                let mut registrar = REGISTRAR.lock().unwrap();
                                let mut authorizer = AUTHORIZER.lock().unwrap();
                                let flow = AuthorizationFlow::new(&mut *registrar, &mut *authorizer);
                                request.handle(flow, handle_post)
                            })
                            .wait()
                            .unwrap_or(httpcodes::HTTPBadRequest.with_body(Body::Empty)),
                        _ => httpcodes::HTTPNotFound.with_body(Body::Empty),
                    }
                })
                .handler("/token", |req: HttpRequest<State>| {
                    match *req.method() {
                        Method::POST => req.oauth2().access_token()
                            .and_then(|request| {
                                let mut registrar = REGISTRAR.lock().unwrap();
                                let mut authorizer = AUTHORIZER.lock().unwrap();
                                let mut issuer = ISSUER.lock().unwrap();
                                let flow = GrantFlow::new(&mut *registrar, &mut *authorizer, &mut *issuer);
                                request.handle(flow)
                            }).wait()
                            .unwrap_or(httpcodes::HTTPBadRequest.with_body(Body::Empty)),
                        _ => httpcodes::HTTPNotFound.with_body(Body::Empty),
                    }
                })
                .handler("/", |req: HttpRequest<State>| {
                    match *req.method() {
                        Method::GET => req.oauth2().guard()
                            .and_then(|guard| {
                                let mut issuer = ISSUER.lock().unwrap();
                                let scopes = vec!["default".parse().unwrap()];
                                let flow = AccessFlow::new(&mut *issuer, scopes.as_slice());
                                guard.handle(flow)
                            })
                            .map(|()| {
                                HttpResponse::Ok()
                                    .content_type("text/plain")
                                    .body("Hello world!")
                                    .unwrap()
                            })
                            .wait()
                            .unwrap_or_else(
                                |_| {
let text = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";
                                HttpResponse::Unauthorized()
                                    .content_type("text/html")
                                    .body(text)
                                    .unwrap()
                            }),
                        _ => httpcodes::HTTPNotFound.with_body(Body::Empty),
                    }
                })
            )
            .bind("localhost:8020")
            .expect("Failed to bind to socket")
            .start();

        HttpServer::new(|| Application::new().handler("/endpoint", dummy_client))
            .bind("localhost:8021")
            .expect("Failed to start dummy client")
            .start();

        let _ = sys.run();
    }

    /// A simple implementation of the first part of an authentication handler. This will
    /// display a page to the user asking for his permission to proceed. The submitted form
    /// will then trigger the other authorization handler which actually completes the flow.
    fn handle_get(_: &HttpRequest<State>, grant: &PreGrant) -> Result<(Authentication, HttpResponse), OAuthError> {
        let text = format!(
            "<html>'{}' (at {}) is requesting permission for '{}'
            <form action=\"authorize?response_type=code&client_id={}\" method=\"post\">
                <input type=\"submit\" value=\"Accept\">
            </form>
            <form action=\"authorize?response_type=code&client_id={}&deny=1\" method=\"post\">
                <input type=\"submit\" value=\"Deny\">
            </form>
            </html>", grant.client_id, grant.redirect_uri, grant.scope, grant.client_id, grant.client_id);
        let response = HttpResponse::Ok()
            .content_type("text/html")
            .body(text)
            .unwrap();
        Ok((Authentication::InProgress, response))
    }

    /// Handle form submission by a user, completing the authorization flow. The resource owner
    /// either accepted or denied the request.
    fn handle_post(request: &HttpRequest<State>, _: &PreGrant) -> Result<(Authentication, HttpResponse), OAuthError> {
        // No real user authentication is done here, in production you SHOULD use session keys or equivalent
        if let Some(_) = request.query().get("deny") {
            Ok((Authentication::Failed,
                HttpResponse::Unauthorized().finish().unwrap()))
        } else {
            Ok((Authentication::Authenticated("dummy user".to_string()),
                HttpResponse::Unauthorized().finish().unwrap()))
        }
    }
}

#[cfg(not(feature = "actix-frontend"))]
mod main { pub fn example() { } }

fn main() {
    main::example();
}
