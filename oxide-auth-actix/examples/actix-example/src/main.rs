mod support;

use actix_web::{middleware::Logger, web, App, HttpRequest, HttpServer};
use futures::{
    channel::{mpsc, oneshot},
    stream::StreamExt,
};
use oxide_auth::{
    endpoint::{Endpoint, OwnerConsent, OwnerSolicitor, PreGrant},
    frontends::simple::endpoint::{ErrorInto, FnSolicitor, Generic, Vacant},
    primitives::grant::Grant,
    primitives::prelude::{AuthMap, Client, ClientMap, RandomGenerator, Scope, TokenMap},
};
use oxide_auth_actix::{
    Authorize, OAuthOperation, OAuthRequest, OAuthResource, OAuthResponse, Refresh, Resource,
    Token, WebError,
};
use std::thread;

static DENY_TEXT: &str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

enum Message {
    AuthorizeGet(Authorize),
    AuthorizePost(Authorize, String),
    Refresh(Refresh),
    Resource(Resource),
    Token(Token),
}

enum Response {
    Error(WebError),
    OAuth(OAuthResponse),
    Grant(Grant),
}

//type ReceiveResponse = oneshot::Receiver<Response>;
type SendResponse = oneshot::Sender<Response>;
type ReceiveMessage = mpsc::UnboundedReceiver<(Message, SendResponse)>;
type SendMessage = mpsc::UnboundedSender<(Message, SendResponse)>;

struct State {
    endpoint: Generic<
        ClientMap,
        AuthMap<RandomGenerator>,
        TokenMap<RandomGenerator>,
        Vacant,
        Vec<Scope>,
        fn() -> OAuthResponse,
    >,
}

async fn get_authorize(
    req: OAuthRequest,
    state: web::Data<SendMessage>,
) -> Result<OAuthResponse, WebError> {
    // GET requests should not mutate server state and are extremely
    // vulnerable accidental repetition as well as Cross-Site Request
    // Forgery (CSRF).
    let (sender, receiver) = oneshot::channel();
    state
        .unbounded_send((Message::AuthorizeGet(Authorize(req)), sender))
        .map_err(|err| WebError::InternalError(Some(format!("send error: {:?}", err))))?;
    match receiver.await {
        Ok(Response::OAuth(resp)) => Ok(resp),
        Ok(Response::Error(err)) => Err(err),
        Ok(_) => Err(WebError::InternalError(Some(
            "Unexpected result".to_string(),
        ))),
        Err(err) => Err(WebError::InternalError(Some(format!(
            "Messaging error {}",
            err
        )))),
    }
}

async fn post_authorize(
    r: HttpRequest,
    req: OAuthRequest,
    state: web::Data<SendMessage>,
) -> Result<OAuthResponse, WebError> {
    // Some authentication should be performed here in production cases
    let (sender, receiver) = oneshot::channel();
    state
        .unbounded_send((
            Message::AuthorizePost(Authorize(req), r.query_string().to_owned()),
            sender,
        ))
        .map_err(|err| WebError::InternalError(Some(format!("send error: {:?}", err))))?;
    match receiver.await {
        Ok(Response::OAuth(resp)) => Ok(resp),
        Ok(Response::Error(err)) => Err(err),
        Ok(_) => Err(WebError::InternalError(Some(
            "Unexpected result".to_string(),
        ))),
        Err(err) => Err(WebError::InternalError(Some(format!(
            "Messaging error {}",
            err
        )))),
    }
}

async fn token(
    req: OAuthRequest,
    state: web::Data<SendMessage>,
) -> Result<OAuthResponse, WebError> {
    let (sender, receiver) = oneshot::channel();
    state
        .unbounded_send((Message::Token(Token(req)), sender))
        .map_err(|err| WebError::InternalError(Some(format!("send error: {:?}", err))))?;
    match receiver.await {
        Ok(Response::OAuth(resp)) => Ok(resp),
        Ok(Response::Error(err)) => Err(err),
        Ok(_) => Err(WebError::InternalError(Some(
            "Unexpected result".to_string(),
        ))),
        Err(err) => Err(WebError::InternalError(Some(format!(
            "Messaging error {}",
            err
        )))),
    }
}

async fn refresh(
    req: OAuthRequest,
    state: web::Data<SendMessage>,
) -> Result<OAuthResponse, WebError> {
    let (sender, receiver) = oneshot::channel();
    state
        .unbounded_send((Message::Refresh(Refresh(req)), sender))
        .map_err(|err| WebError::InternalError(Some(format!("send error: {:?}", err))))?;
    match receiver.await {
        Ok(Response::OAuth(resp)) => Ok(resp),
        Ok(Response::Error(err)) => Err(err),
        Ok(_) => Err(WebError::InternalError(Some(
            "Unexpected result".to_string(),
        ))),
        Err(err) => Err(WebError::InternalError(Some(format!(
            "Messaging error {}",
            err
        )))),
    }
}

async fn index(
    req: OAuthResource,
    state: web::Data<SendMessage>,
) -> Result<OAuthResponse, WebError> {
    let (sender, receiver) = oneshot::channel();
    state
        .unbounded_send((Message::Resource(Resource(req.into_request())), sender))
        .map_err(|err| WebError::InternalError(Some(format!("send error: {:?}", err))))?;
    match receiver.await {
        Ok(Response::Grant(_grant)) => Ok(OAuthResponse::ok()
            .content_type("text/plain")?
            .body("Hello world!")),
        Ok(Response::OAuth(err)) => Ok(err.body(DENY_TEXT)),
        Ok(_) => {
            return Err(WebError::InternalError(Some(
                "Unexpected result".to_string(),
            )))
        }
        Err(err) => {
            return Err(WebError::InternalError(Some(format!(
                "Messaging error {}",
                err
            ))))
        }
    }
}

async fn start_browser() -> () {
    let _ = thread::spawn(support::open_in_browser);
}

async fn start_db(mut state: State, mut rx: ReceiveMessage) -> () {
    while let Some((m, f)) = rx.next().await {
        let resp = state.process_message(m);
        let _ = f.send(resp);
    }
}

/// Example of a main function of an actix-web server supporting oauth.
pub fn main() {
    std::env::set_var(
        "RUST_LOG",
        "actix_example=info,actix_web=info,actix_http=info,actix_service=info",
    );
    env_logger::init();

    let mut sys = actix_rt::System::new("HttpServerClient");

    // Start, then open in browser, don't care about this finishing.
    let _ = sys.block_on(start_browser());    

    let (sender, receiver) = mpsc::unbounded();
    let state = State::preconfigured();
    let _ = actix_rt::spawn(start_db(state, receiver));

    // Create the main server instance
    HttpServer::new(move || {
        App::new()
            .data(sender.clone())
            .wrap(Logger::default())
            .service(
                web::resource("/authorize")
                    .route(web::get().to(get_authorize))
                    .route(web::post().to(post_authorize)),
            )
            .route("/token", web::post().to(token))
            .route("/refresh", web::post().to(refresh))
            .route("/", web::get().to(index))
    })
    .bind("localhost:8020")
    .expect("Failed to bind to socket")
    .start();

    support::dummy_client();

    // Run the rest of the system.
    let _ = sys.run();
}

impl State {
    pub fn preconfigured() -> Self {
        State {
            endpoint: Generic {
                // A registrar with one pre-registered client
                registrar: vec![Client::public(
                    "LocalClient",
                    "http://localhost:8021/endpoint".parse().unwrap(),
                    "default-scope".parse().unwrap(),
                )]
                .into_iter()
                .collect(),
                // Authorization tokens are 16 byte random keys to a memory hash map.
                authorizer: AuthMap::new(RandomGenerator::new(16)),
                // Bearer tokens are also random generated but 256-bit tokens, since they live longer
                // and this example is somewhat paranoid.
                //
                // We could also use a `TokenSigner::ephemeral` here to create signed tokens which can
                // be read and parsed by anyone, but not maliciously created. However, they can not be
                // revoked and thus don't offer even longer lived refresh tokens.
                issuer: TokenMap::new(RandomGenerator::new(16)),

                solicitor: Vacant,

                // A single scope that will guard resources for this endpoint
                scopes: vec!["default-scope".parse().unwrap()],

                response: OAuthResponse::ok,
            },
        }
    }

    fn with_solicitor<'a, S>(
        &'a mut self,
        solicitor: S,
    ) -> impl Endpoint<OAuthRequest, Error = WebError> + 'a
    where
        S: OwnerSolicitor<OAuthRequest> + 'static,
    {
        ErrorInto::new(Generic {
            authorizer: &mut self.endpoint.authorizer,
            registrar: &mut self.endpoint.registrar,
            issuer: &mut self.endpoint.issuer,
            solicitor,
            scopes: &mut self.endpoint.scopes,
            response: OAuthResponse::ok,
        })
    }

    pub fn process_message(&mut self, msg: Message) -> Response {
        match msg {
            Message::AuthorizeGet(op) => {
                let solicitor = FnSolicitor(move |_: &mut OAuthRequest, pre_grant: &PreGrant| {
                    // This will display a page to the user asking for his permission to proceed. The submitted form
                    // will then trigger the other authorization handler which actually completes the flow.
                    OwnerConsent::InProgress(
                        OAuthResponse::ok().content_type("text/html").unwrap().body(
                            &crate::support::consent_page_html("/authorize".into(), pre_grant),
                        ),
                    )
                });

                match op.run(self.with_solicitor(solicitor)) {
                    Ok(resp) => Response::OAuth(resp),
                    Err(err) => Response::Error(err),
                }
            }
            Message::AuthorizePost(op, query_string) => {
                let solicitor = FnSolicitor(move |_: &mut OAuthRequest, _: &PreGrant| {
                    if query_string.contains("allow") {
                        OwnerConsent::Authorized("dummy user".to_owned())
                    } else {
                        OwnerConsent::Denied
                    }
                });

                match op.run(self.with_solicitor(solicitor)) {
                    Ok(resp) => Response::OAuth(resp),
                    Err(err) => Response::Error(err),
                }
            }
            Message::Token(op) => match op.run(&mut self.endpoint) {
                Ok(resp) => Response::OAuth(resp),
                Err(err) => Response::Error(err),
            },
            Message::Refresh(op) => match op.run(&mut self.endpoint) {
                Ok(resp) => Response::OAuth(resp),
                Err(err) => Response::Error(err),
            },
            Message::Resource(op) => match op.run(&mut self.endpoint) {
                Ok(resp) => Response::Grant(resp),
                Err(Ok(err)) => Response::OAuth(err),
                Err(Err(err)) => Response::Error(err),
            },
        }
    }
}
