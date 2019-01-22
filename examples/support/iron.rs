extern crate iron;
extern crate reqwest;
extern crate serde;
extern crate serde_json;

#[path = "./generic.rs"]
mod generic;

pub use self::generic::*;

use std::collections::HashMap;
use std::io::Read;
use self::iron::prelude::*;
use self::iron::{headers, modifiers, status};
use self::reqwest::header::Authorization;

/// Rough client function mirroring core functionality of an oauth client. This is not actually
/// needed in your implementation but merely exists to provide an interactive example. It will
/// always identify itself as `LocalClient` with redirect url `http://localhost:8021/endpoint`.
pub fn dummy_client(req: &mut Request) -> IronResult<Response> {
    // Check the received parameters in the input
    let query = req.url.as_ref().query_pairs().collect::<HashMap<_, _>>();
    if let Some(error) = query.get("error") {
        let message = "Error during owner authorization: ".to_string() + error.as_ref();
        return Ok(Response::with((status::Ok, message)));
    };
    let code = match query.get("code") {
        None => return Ok(Response::with((status::BadRequest, "Missing code"))),
        Some(v) => v.clone()
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
    let mut token_response = client.execute(access_token_request).unwrap();
    let mut token = String::new();
    token_response.read_to_string(&mut token).unwrap();
    let token_map: HashMap<String, String> = serde_json::from_str(&token).unwrap();

    if token_map.get("error").is_some() || !token_map.get("access_token").is_some() {
        return Ok(Response::with((status::BadRequest, token)));
    }

    // Request the page with the oauth token
    let page_request = client
        .get("http://localhost:8020/")
        .header(Authorization("Bearer ".to_string() + token_map.get("access_token").unwrap()))
        .build().unwrap();
    let mut page_response = client.execute(page_request).unwrap();
    let mut protected_page = String::new();
    page_response.read_to_string(&mut protected_page).unwrap();

    let token = serde_json::to_string_pretty(&token_map).unwrap();
    let token = token.replace(",", ",</br>");
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
        </main></html>", token, protected_page);

    Ok(Response::with((
        status::Ok,
        modifiers::Header(headers::ContentType::html()),
        display_page,
    )))
}
