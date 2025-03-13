use std::sync::{Arc};
use poem::{get, handler, post, EndpointExt, IntoResponse, Route};
use poem::http::StatusCode;
use poem::web::{Data, Query};
use serde::Deserialize;

#[path = "../../../examples/support/generic.rs"]
mod generic;

pub use self::generic::{consent_page_html, open_in_browser};

use self::generic::{Client, ClientConfig};

#[derive(Deserialize)]
struct EndpointQuery {
    error: Option<String>,
    code: Option<String>,
}

#[handler]
async fn endpoint_handler(
    Query(EndpointQuery { error, code }): Query<EndpointQuery>, client: Data<&Arc<Client>>,
) -> poem::Result<poem::Response> {
    if let Some(error) = error {
        let message = format!("Error during authorization: {}", error);
        return Ok((StatusCode::OK, message).into());
    }

    let code = code.ok_or_else(|| poem::Error::from_string("Missing code", StatusCode::BAD_REQUEST))?;

    let client = client.clone();

    let auth_handle = tokio::task::spawn_blocking(move || client.authorize(&code));

    auth_handle
        .await
        .unwrap()
        .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(poem::web::Redirect::see_other("/").into_response())
}

#[handler]
async fn refresh_handler(client: Data<&Arc<Client>>) -> poem::Result<poem::Response> {
    let client = client.clone();

    let refresh_handle = tokio::task::spawn_blocking(move || client.refresh());

    refresh_handle
        .await
        .unwrap()
        .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(poem::web::Redirect::see_other("/").into_response())
}

#[handler]
async fn index_handler(client: Data<&Arc<Client>>) -> poem::Result<poem::Response> {
    let html = client.as_html();

    let protected_client = client.clone();

    let protected_page_handle =
        tokio::task::spawn_blocking(move || protected_client.retrieve_protected_page());
    let protected_page_result = protected_page_handle.await.unwrap();

    let protected_page = protected_page_result
        .map_err(|err| poem::Error::from_string(err.to_string(), StatusCode::OK))?;

    let protected_url = client.config.protected_url.as_str();

    let display_page = format!(
        "<html><style>
            aside{{overflow: auto; word-break: keep-all; white-space: nowrap}}
            main{{text-align: center}}
            main>aside,main>article{{margin: auto; text-align: left; border: 1px solid black; width: 50%}}
        </style>
        <main>
        Used token <aside style>{html}</aside> to access
        <a href=\"{protected_url}\">{protected_url}</a>.
        Its contents are:
        <article>{protected_page}</article>
        <form action=\"/refresh\" method=\"post\"><button>Refresh token</button></form>
        </main></html>");

    Ok(poem::Response::builder()
        .content_type("text/html")
        .body(display_page))
}

pub fn dummy_client_routes(client_port: u16, server_port: u16) -> impl poem::Endpoint {
    let client = Arc::new(Client::new(ClientConfig {
        client_id: "LocalClient".into(),
        client_secret: Some("SecretSecret".to_owned()),
        protected_url: format!("http://localhost:{server_port}/"),
        token_url: format!("http://localhost:{server_port}/token"),
        refresh_url: format!("http://localhost:{server_port}/token"),
        redirect_uri: format!("http://localhost:{client_port}/endpoint"),
    }));

    Route::new()
        .at("/endpoint", get(endpoint_handler))
        .at("/refresh", post(refresh_handler))
        .at("/", get(index_handler))
        .data(client)
}
