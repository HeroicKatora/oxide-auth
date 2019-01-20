extern crate reqwest;
extern crate actix_web;
extern crate serde;
extern crate serde_json;

#[path="generic.rs"]
mod generic;

pub use self::generic::*;

use self::reqwest::header;
use self::actix_web::*;
use self::actix_web::App;

use std::collections::HashMap;
use std::io::Read;
use std::sync::RwLock;

#[derive(Default)]
pub struct State {
    token: RwLock<Option<String>>,
    token_map: RwLock<Option<String>>,
}

pub fn dummy_client() -> App<State> {
    App::with_state(State::default())
        .handler("/endpoint", endpoint_impl)
        .handler("/", get_with_token)
}

fn endpoint_impl(request: &HttpRequest<State>) -> HttpResponse {
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
    let mut token_response = match client.execute(access_token_request) {
        Ok(response) => response,
        Err(_) => return HttpResponse::BadRequest()
            .body("Could not fetch bearer token"),
    };
    let mut token = String::new();
    token_response.read_to_string(&mut token).unwrap();
    let token_map: HashMap<String, String> = match serde_json::from_str(&token) {
        Ok(token_map) => token_map,
        Err(err) => return HttpResponse::BadRequest()
            .body(format!("Error unwrapping json response, got {:?} instead", err)),
    };

    if token_map.get("error").is_some() || !token_map.get("access_token").is_some() {
        return HttpResponse::BadRequest()
            .body(token);
    }

    let token = token_map.get("access_token").unwrap();
    let token_map = serde_json::to_string_pretty(&token_map).unwrap();
    let token_map = token_map.replace(",", ",</br>");

    let mut set_map = request.state().token_map.write().unwrap();
    *set_map = Some(token_map);

    let mut set_token = request.state().token.write().unwrap();
    *set_token = Some(token.to_string());

    HttpResponse::Found()
        .header("Location", "/")
        .finish()
}

fn get_with_token(request: &HttpRequest<State>) -> HttpResponse {
    let token = request.state().token.read().unwrap();
    let token = match *token {
        None => return HttpResponse::Ok().body("No token yet"),
        Some(ref token) => token,
    };

    let token_map = request.state().token_map.read().unwrap();
    let token_map = token_map.as_ref().unwrap();

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
        </main></html>", token_map, protected_page);

    HttpResponse::Ok()
        .content_type("text/html")
        .body(display_page)
}
