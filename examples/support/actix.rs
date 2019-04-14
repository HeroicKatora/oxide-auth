extern crate reqwest;
extern crate actix_web;
extern crate serde;
extern crate serde_json;

#[path="generic.rs"]
mod generic;

pub use self::generic::*;

use self::reqwest::{header, Response};
use self::actix_web::*;
use self::actix_web::App;

use std::fmt;
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, RwLock};

#[derive(Debug, Default)]
pub struct State {
    token: Option<String>,
    refresh: Option<String>,
    until: Option<String>,
}

type AppState = Arc<RwLock<State>>;

pub fn dummy_client() -> App<AppState> {
    App::with_state(AppState::default())
        .route("/endpoint", http::Method::GET, |req| endpoint_impl(&req))
        .route("/refresh", http::Method::POST, |req| refresh(&req))
        .route("/", http::Method::GET, |req| get_with_token(&req))
}

fn endpoint_impl(request: &HttpRequest<AppState>) -> HttpResponse {
    if let Some(cause) = request.query().get("error") {
        return HttpResponse::BadRequest()
            .body(format!("Error during owner authorization: {:?}", cause))
    }

    let code = match request.query().get("code") {
        None => return HttpResponse::BadRequest()
            .body("Missing code"),
        Some(code) => code.clone(),
    };

    // Construct a request against http://localhost:8020/token, the access token endpoint
    let client = reqwest::Client::new();
    let mut params = HashMap::new();
    params.insert("grant_type", "authorization_code");
    params.insert("client_id", "LocalClient");
    params.insert("code", &code);
    params.insert("redirect_uri", "http://localhost:8021/endpoint");
    let access_token_request = client
        .post("http://localhost:8020/token")
        .form(&params).build().unwrap();

    let token_response = match client.execute(access_token_request) {
        Ok(response) => response,
        Err(_) => return HttpResponse::BadRequest()
            .body("Could not fetch bearer token"),
    };

    let token_map = match parse_response(token_response) {
        Ok(map) => map,
        Err(err) => return err,
    };

    if token_map.get("error").is_some() || !token_map.get("access_token").is_some() {
        return HttpResponse::BadRequest()
            .body(format!("Response contains neither error nor access token: {:?}", token_map));
    }

    let token = token_map.get("access_token").unwrap();

    let mut set_map = request.state().write().unwrap();
    set_map.token = Some(token.to_string());
    set_map.refresh = token_map
        .get("refresh_token")
        .cloned();
    set_map.until = token_map
        .get("expires_in")
        .cloned();

    HttpResponse::Found()
        .header("Location", "/")
        .finish()
}

fn refresh(request: &HttpRequest<AppState>) -> HttpResponse {
    let refresh = match request.state().read().unwrap().refresh.clone() {
        Some(refresh) => refresh,
        None => return HttpResponse::BadRequest()
            .body("No refresh token was issued"),
    };

    let client = reqwest::Client::new();
    let mut params = HashMap::new();
    params.insert("grant_type", "refresh_token");
    params.insert("client_id", "LocalClient");
    params.insert("refresh_token", &refresh);
    let access_token_request = client
        .post("http://localhost:8020/refresh")
        .form(&params).build().unwrap();

    let token_response = match client.execute(access_token_request) {
        Ok(response) => response,
        Err(_) => return HttpResponse::BadRequest()
            .body("Could not refresh bearer token"),
    };

    let token_map = match parse_response(token_response) {
        Ok(map) => map,
        Err(err) => return err,
    };

    if token_map.get("error").is_some() || !token_map.get("access_token").is_some() {
        return HttpResponse::BadRequest()
            .body(format!("Response contains neither error nor access token: {:?}", token_map));
    }

    let token = token_map.get("access_token").unwrap();

    let mut set_map = request.state().write().unwrap();
    set_map.token = Some(token.to_string());
    set_map.refresh = token_map
        .get("refresh_token")
        .cloned()
        .or(set_map.refresh.take());
    set_map.until = token_map
        .get("expires_in")
        .cloned();

    HttpResponse::Found()
        .header("Location", "/")
        .finish()
}

fn get_with_token(request: &HttpRequest<AppState>) -> HttpResponse {
    let state = request.state().read().unwrap();

    let token = match state.token {
        None => return HttpResponse::Ok().body("No token yet"),
        Some(ref token) => token,
    };

    let client = reqwest::Client::new();
    // Request the page with the oauth token
    let page_request = client
        .get("http://localhost:8020/")
        .header(header::AUTHORIZATION, "Bearer ".to_string() + token)
        .build()
        .unwrap();
    let mut page_response = match client.execute(page_request) {
        Ok(response) => response,
        Err(_) => return HttpResponse::BadRequest()
            .body("Could not access protected resource"),
    };
    let mut protected_page = String::new();
    page_response.read_to_string(&mut protected_page).unwrap();

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
        </main></html>", state, protected_page);

    HttpResponse::Ok()
        .content_type("text/html")
        .body(display_page)
}

fn parse_response(mut response: Response) -> Result<HashMap<String, String>, HttpResponse> {
    let mut token = String::new();
    response.read_to_string(&mut token).unwrap();
    serde_json::from_str(&token).map_err(|err| {
        HttpResponse::BadRequest()
            .body(format!("Error unwrapping json response, got {:?} instead", err))
    })
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Token {<br>")?;
        write!(f, "&nbsp;token: {:?},<br>", self.token)?;
        write!(f, "&nbsp;refresh: {:?},<br>", self.refresh)?;
        write!(f, "&nbsp;expires_in: {:?},<br>", self.until)?;
        f.write_str("}")
    }
}
