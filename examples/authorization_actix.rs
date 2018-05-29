 mod support;
#[macro_use]
extern crate lazy_static;

#[cfg(feature = "actix-frontend")]
mod main {
    extern crate actix;
    extern crate actix_web;
    extern crate futures;
    extern crate oxide_auth;
    extern crate url;

    use super::support::actix::dummy_client;
    use self::actix::{Actor, Addr, Unsync, Syn};
    use self::actix_web::{server, App, Body, HttpRequest, HttpResponse, Error as AWError};
    use self::actix_web::http::Method;
    use self::futures::Future;
    use self::oxide_auth::frontends::actix::*;
    use self::oxide_auth::code_grant::frontend::{OAuthError, OwnerAuthorization};
    use self::oxide_auth::primitives::prelude::*;

    static PASSPHRASE: &str = "This is a super secret phrase";
    static DENY_TEXT: &str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

    /// Example of a main function of a rouille server supporting oauth.
    pub fn example() {
        let sys = actix::System::new("HttpServer");

        let mut clients  = ClientMap::new();
        // Register a dummy client instance
        let client = Client::public("LocalClient", // Client id
            "http://localhost:8021/endpoint".parse().unwrap(), // Redirection url
            "default".parse().unwrap()); // Allowed client scope
        clients.register_client(client);

        let authorizer = Storage::new(RandomGenerator::new(16));
        let issuer = TokenSigner::new_from_passphrase(&PASSPHRASE, None);
        let scopes = vec!["default".parse().unwrap()].into_boxed_slice();

        // Emulate static initialization for complex type
        let scopes: &'static _ = Box::leak(scopes);

        let endpoint: Addr<Syn,_> = CodeGrantEndpoint::new((clients, authorizer, issuer))
            .with_authorization(|&mut (ref client, ref mut authorizer, _)| {
                let primitives = AuthorizationPrimitives::new(client, authorizer);
                AuthorizationFlow::new(&primitives)
            })
            .with_grant(|&mut (ref client, ref mut authorizer, ref mut issuer)| {
                GrantFlow::new(client, authorizer, issuer)
            })
            .with_guard(move |&mut (_, _, ref mut issuer)| {
                AccessFlow::new(issuer, scopes)
            })
            .start();

        // Create the main server instance
        server::new(
            move || App::with_state(endpoint.clone())
                .route("/authorize", Method::GET, |req: HttpRequest<_>| {
                    let endpoint = req.state().clone();
                    Box::new(req.oauth2()
                        .authorization_code()
                        .and_then(move |request| endpoint.send(request)
                            .or_else(|_| Err(OAuthError::AccessDenied))
                            .and_then(|result| result.and_then(ResolvedResponse::into))
                        )
                        .or_else(|_| Ok(HttpResponse::BadRequest().body(Body::Empty)))
                    ) as Box<Future<Item = HttpResponse, Error = AWError>>
                })
                .route("/authorize", Method::POST, |req: HttpRequest<_>| {
                    let endpoint = req.state().clone();
                    Box::new(req.oauth2()
                        .authorization_code()
                        .and_then(move |request| endpoint.send(request)
                            .or_else(|_| Err(OAuthError::AccessDenied))
                            .and_then(|result| result.and_then(ResolvedResponse::into))
                        )
                        .or_else(|_| Ok(HttpResponse::BadRequest().body(Body::Empty)))
                    ) as Box<Future<Item = HttpResponse, Error = AWError>>
                })
                .route("/token", Method::POST, |req: HttpRequest<_>| {
                    let endpoint = req.state().clone();
                    Box::new(req.oauth2()
                        .access_token()
                        .and_then(move |request| endpoint.send(request)
                            .or_else(|_| Err(OAuthError::AccessDenied))
                            .and_then(|result| result.and_then(ResolvedResponse::into))
                        )
                        .or_else(|_| Ok(HttpResponse::BadRequest().body(Body::Empty)))
                    ) as Box<Future<Item = HttpResponse, Error = AWError>>
                })
                .route("/", Method::GET, |req: HttpRequest<_>| {
                    let endpoint = req.state().clone();
                    Box::new(req.oauth2()
                        .guard()
                        .and_then(move |request| endpoint.send(request)
                            .or_else(|_| Err(OAuthError::AccessDenied))
                            .and_then(|result| result)
                        ).map(|()|
                            HttpResponse::Ok()
                                .content_type("text/plain")
                                .body("Hello world!")
                        ).or_else(|_|
                            Ok(HttpResponse::Unauthorized()
                                .content_type("text/html")
                                .body(DENY_TEXT))
                        )
                    ) as Box<Future<Item = HttpResponse, Error = AWError>>
                })
            )
            .bind("localhost:8020")
            .expect("Failed to bind to socket")
            .start();

        server::new(|| App::new().handler("/endpoint", dummy_client))
            .bind("localhost:8021")
            .expect("Failed to start dummy client")
            .start();

        let _ = sys.run();
    }
/*
    /// A simple implementation of the first part of an authentication handler. This will
    /// display a page to the user asking for his permission to proceed. The submitted form
    /// will then trigger the other authorization handler which actually completes the flow.
    fn handle_get(_: &HttpRequest, grant: &PreGrant) -> OwnerAuthorization<HttpResponse> {
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
            .body(text);
        OwnerAuthorization::InProgress(response)
    }

    /// Handle form submission by a user, completing the authorization flow. The resource owner
    /// either accepted or denied the request.
    fn handle_post(request: &HttpRequest, _: &PreGrant) -> OwnerAuthorization<HttpResponse> {
        // No real user authentication is done here, in production you SHOULD use session keys or equivalent
        if let Some(_) = request.query().get("deny") {
            OwnerAuthorization::Denied
        } else {
            OwnerAuthorization::Authorized("dummy user".to_string())
        }
    }*/
}

#[cfg(not(feature = "actix-frontend"))]
mod main { pub fn example() { } }

fn main() {
    main::example();
}
