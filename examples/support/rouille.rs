extern crate reqwest;
extern crate rouille;
extern crate serde_urlencoded;
extern crate serde;
extern crate serde_json;

use self::reqwest::header;
use self::rouille::{Request, Response};

use std::collections::HashMap;
use std::io::Read;

pub fn dummy_client(request: &Request) -> Response {
    if let Some(cause) = request.get_param("error") {
        return Response::text(format!("Error during owner authorization: {:?}", cause))
    }

    let code = match request.get_param("code") {
        None => return Response::text("Missing code").with_status_code(400),
        Some(code) => code,
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
        return Response::text(token).with_status_code(400);
    }

    // Request the page with the oauth token
    let page_request = client
        .get("http://localhost:8020/")
        .header(header::AUTHORIZATION, "Bearer ".to_string() + token_map.get("access_token").unwrap())
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

    Response::html(display_page)
        .with_status_code(200)
}
