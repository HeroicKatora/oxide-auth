extern crate reqwest;
extern crate rouille;
extern crate serde_urlencoded;
extern crate serde;
extern crate serde_json;

#[path="generic.rs"]
mod generic;

pub use self::generic::{Client, ClientConfig, ClientError};
pub use self::generic::{consent_page_html, open_in_browser};

use self::rouille::{Request, Response};

pub fn dummy_client()
    -> impl (Fn(&Request) -> Response) + 'static
{
    let client = Client::new(ClientConfig {
        client_id: "LocalClient".into(),
        protected_url: "http://localhost:8020/".into(),
        token_url: "http://localhost:8020/token".into(),
        refresh_url: "http://localhost:8020/refresh".into(),
        redirect_uri: "http://localhost:8021/endpoint".into(),
    });

    move |request| {
        router!(request,
            (GET) ["/"] => {
                client_impl(&client, request)
            },
            (GET) ["/endpoint"] => {
                endpoint_impl(&client, request)
            },
            (POST) ["/refresh"] => {
                refresh_impl(&client, request)
            },
            _ => Response::empty_404(),
        )
    }
}

pub fn client_impl(client: &Client, _: &Request) -> Response {
    let protected_page = match client.retrieve_protected_page() {
        Ok(page) => page,
        Err(err) => return internal_error(err),
    };

    let display_page = format!(
        "<html><style>
            aside{{overflow: auto; word-break: keep-all; white-space: nowrap}}
            main{{text-align: center}}
            main>aside,main>article{{margin: auto; text-align: left; border: 1px solid black; width: 50%}}
        </style>
        <main>
        Used token <aside style>{}</aside> to access
        <a href=\"http://localhost:8020/\">http://localhost:8020/</a>.
        Its contents are:
        <article>{:?}</article>
        <form action=\"/refresh\" method=\"post\"><button>Refresh token</button></form>
        </main></html>", client.as_html(), protected_page);

    Response::html(display_page)
        .with_status_code(200)
}

fn endpoint_impl(client: &Client, request: &Request) -> Response {
    if let Some(error) = request.get_param("error") {
        return Response::text(format!("Error during owner authorization: {:?}", error))
            .with_status_code(400);
    }

    let code = match request.get_param("code") {
        Some(code) => code,
        None => return Response::text("Endpoint hit without an authorization code")
            .with_status_code(400),
    };

    if let Err(err) = client.authorize(&code) {
        return internal_error(err);
    }

    Response::redirect_303("/")
}

fn refresh_impl(client: &Client, _: &Request) -> Response {
    client.refresh()
        .err()
        .map_or_else(|| Response::redirect_303("/"), internal_error)
}

fn internal_error(error: ClientError) -> Response {
    Response::text(error.to_string()).with_status_code(500)
}
