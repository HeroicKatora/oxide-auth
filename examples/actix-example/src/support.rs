extern crate actix_web;

#[path = "../../support/generic.rs"]
mod generic;

pub use self::generic::{consent_page_html, open_in_browser, Client, ClientConfig, ClientError};

use self::actix_web::App;
use self::actix_web::*;

pub fn dummy_client() -> App<Client> {
    let config = ClientConfig {
        client_id: "LocalClient".into(),
        protected_url: "http://localhost:8020/".into(),
        token_url: "http://localhost:8020/token".into(),
        refresh_url: "http://localhost:8020/refresh".into(),
        redirect_uri: "http://localhost:8021/endpoint".into(),
    };

    App::with_state(Client::new(config))
        .route("/endpoint", http::Method::GET, endpoint_impl)
        .route("/refresh", http::Method::POST, refresh)
        .route("/", http::Method::GET, get_with_token)
}

fn endpoint_impl(request: HttpRequest<Client>) -> HttpResponse {
    if let Some(cause) = request.query().get("error") {
        return HttpResponse::BadRequest()
            .body(format!("Error during owner authorization: {:?}", cause));
    }

    let code = match request.query().get("code") {
        None => return HttpResponse::BadRequest().body("Missing code"),
        Some(code) => code.clone(),
    };

    match request.state().authorize(&code) {
        Ok(()) => HttpResponse::Found().header("Location", "/").finish(),
        Err(err) => HttpResponse::InternalServerError().body(format!("{}", err)),
    }
}

fn refresh(request: HttpRequest<Client>) -> HttpResponse {
    match request.state().refresh() {
        Ok(()) => HttpResponse::Found().header("Location", "/").finish(),
        Err(err) => HttpResponse::InternalServerError().body(format!("{}", err)),
    }
}

fn get_with_token(request: HttpRequest<Client>) -> HttpResponse {
    let state = request.state();
    let protected_page = match state.retrieve_protected_page() {
        Ok(page) => page,
        Err(err) => return HttpResponse::InternalServerError().body(format!("{}", err)),
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
        <article>{}</article>
        <form action=\"refresh\" method=\"post\"><button>Refresh token</button></form>
        </main></html>", state.as_html(), protected_page);

    HttpResponse::Ok()
        .content_type("text/html")
        .body(display_page)
}
