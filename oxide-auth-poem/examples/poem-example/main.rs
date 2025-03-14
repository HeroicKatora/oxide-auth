use std::sync::{Arc, Mutex};
use poem::{get, handler, post, EndpointExt, Route, Server};
use poem::listener::TcpListener;
use poem::middleware::AddDataEndpoint;
use poem::web::Data;
use oxide_auth::endpoint::{
    Authorizer, Issuer, OwnerConsent, QueryParameter, Registrar, Solicitation, WebResponse,
};
use oxide_auth::frontends::simple::endpoint::{FnSolicitor, Generic, Vacant};
use oxide_auth::primitives::{
    authorizer::AuthMap, generator::RandomGenerator, issuer::TokenMap, prelude::ClientMap,
    prelude::Client,
};
use oxide_auth_poem::error::OAuthError;
use oxide_auth_poem::request::OAuthRequest;
use oxide_auth_poem::response::OAuthResponse;

mod support;

struct EndpointState {
    registrar: Mutex<ClientMap>,
    authorizer: Mutex<AuthMap<RandomGenerator>>,
    issuer: Mutex<TokenMap<RandomGenerator>>,
}

impl EndpointState {
    const DENY_TEXT: &'static str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

    fn preconfigured(client_port: u16) -> Self {
        EndpointState {
            registrar: Mutex::new(
                vec![Client::confidential(
                    "LocalClient",
                    format!("http://localhost:{client_port}/endpoint")
                        .parse::<url::Url>()
                        .unwrap()
                        .into(),
                    "default-scope".parse().unwrap(),
                    "SecretSecret".as_bytes(),
                )]
                .into_iter()
                .collect(),
            ),
            authorizer: Mutex::new(AuthMap::new(RandomGenerator::new(16))),
            issuer: Mutex::new(TokenMap::new(RandomGenerator::new(16))),
        }
    }

    /// In larger app, you'd likey wrap it in your own Endpoint instead of `Generic`.
    pub fn endpoint(&self) -> Generic<impl Registrar + '_, impl Authorizer + '_, impl Issuer + '_> {
        Generic {
            registrar: self.registrar.lock().unwrap(),
            authorizer: self.authorizer.lock().unwrap(),
            issuer: self.issuer.lock().unwrap(),
            // Solicitor configured later.
            solicitor: Vacant,
            // Scope configured later.
            scopes: Vacant,
            // OAuthResponse is Default
            response: Vacant,
        }
    }
}

fn consent_form(_: &mut OAuthRequest, solicitation: Solicitation) -> OwnerConsent<OAuthResponse> {
    let mut response = OAuthResponse::default();
    if let Err(e) = response.ok() {
        return OwnerConsent::Error(e);
    }
    response = match response.content_type("text/html") {
        Ok(t) => t,
        Err(e) => return OwnerConsent::Error(e),
    };
    response = response.body(&support::consent_page_html("/authorize", solicitation));

    OwnerConsent::InProgress(response)
}

fn consent_decision(request: &mut OAuthRequest, _: Solicitation) -> OwnerConsent<OAuthResponse> {
    // Authenticate the request better in a real app!
    let allowed = request.query().and_then(|q| q.unique_value("allow")).is_some();
    if allowed {
        OwnerConsent::Authorized("dummy user".into())
    } else {
        OwnerConsent::Denied
    }
}

#[handler]
fn get_authorize(
    request: OAuthRequest, state: Data<&Arc<EndpointState>>,
) -> poem::Result<OAuthResponse> {
    state
        .endpoint()
        .with_solicitor(FnSolicitor(consent_form))
        .authorization_flow()
        .execute(request)
        .map_err(|e| {
            let e: OAuthError = e.into();
            e.into()
        })
}

#[handler]
fn post_authorize(
    request: OAuthRequest, state: Data<&Arc<EndpointState>>,
) -> poem::Result<OAuthResponse> {
    state
        .endpoint()
        .with_solicitor(FnSolicitor(consent_decision))
        .authorization_flow()
        .execute(request)
        .map_err(|e| {
            let e: OAuthError = e.into();
            e.into()
        })
}

#[handler]
fn token_handler(
    request: OAuthRequest, state: Data<&Arc<EndpointState>>,
) -> poem::Result<OAuthResponse> {
    let grant_type = request.body().and_then(|body| body.unique_value("grant_type"));

    match grant_type.as_deref() {
        Some("authorization_code") => {
            state
                .endpoint()
                .access_token_flow()
                .execute(request)
                .map_err(|e| {
                    let e: OAuthError = e.into();
                    e.into()
                })
        }
        _ => state.endpoint().refresh_flow().execute(request).map_err(|e| {
            let e: OAuthError = e.into();
            e.into()
        }),
    }
}

#[handler]
fn get_index(request: OAuthRequest, state: Data<&Arc<EndpointState>>) -> poem::Result<OAuthResponse> {
    let protect = state
        .endpoint()
        .with_scopes(vec!["default-scope".parse().unwrap()])
        .resource_flow()
        .execute(request);

    let _grant = match protect {
        Ok(grant) => grant,
        Err(Ok(mut response)) => {
            return Ok(response
                .content_type("text/html")
                .unwrap()
                .body(EndpointState::DENY_TEXT));
        }
        Err(Err(error)) => {
            let error: OAuthError = error.into();
            return Err(error.into());
        }
    };

    let mut resp = OAuthResponse::default();
    resp.ok()?;
    resp.body_text("Hello, world!")?;

    Ok(resp)
}

fn main_router(client_port: u16) -> AddDataEndpoint<Route, Arc<EndpointState>> {
    let state = Arc::new(EndpointState::preconfigured(client_port));

    Route::new()
        .at("/authorize", get(get_authorize).post(post_authorize))
        .at("/token", post(token_handler))
        .at("/", get(get_index))
        .data(state)
}

async fn start_server(client_port: u16, server_port: u16) -> tokio::io::Result<()> {
    Server::new(TcpListener::bind(("::", server_port)))
        .name("oauth-server")
        .run(main_router(client_port))
        .await
}

async fn start_client(client_port: u16, server_port: u16) -> tokio::io::Result<()> {
    Server::new(TcpListener::bind(("::", client_port)))
        .name("oauth-client")
        .run(support::dummy_client_routes(client_port, server_port))
        .await
}

#[tokio::main]
async fn main() {
    const SERVER_PORT: u16 = 3000;
    const CLIENT_PORT: u16 = 3001;

    let server_handle = tokio::spawn(start_server(CLIENT_PORT, SERVER_PORT));
    let client_handle = tokio::spawn(start_client(CLIENT_PORT, SERVER_PORT));

    let browser_handle: tokio::task::JoinHandle<tokio::io::Result<()>> = tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        support::open_in_browser(SERVER_PORT);

        Ok(())
    });

    match tokio::try_join!(server_handle, client_handle, browser_handle) {
        Ok(_) => {
            // noop
        }
        Err(err) => {
            println!("Failed with {}", err);
        }
    }
}
