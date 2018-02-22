extern crate reqwest;
extern crate actix_web;
extern crate serde;
extern crate serde_json;

use self::reqwest::header::Authorization;
use self::actix_web::*;

use std::collections::HashMap;
use std::io::Read;

pub fn dummy_client(request: HttpRequest) -> HttpResponse {
    if let Some(cause) = request.query().get("error") {
        return HttpResponse::BadRequest()
            .body(format!("Error during owner authorization: {:?}", cause))
            .unwrap()
    }

    let code = match request.query().get("code") {
        None => return HttpResponse::BadRequest()
            .body("Missing code")
            .unwrap(),
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
        return HttpResponse::BadRequest()
            .body(token)
            .unwrap();
    }

    // Request the page with the oauth token
    let page_request = client
        .get("http://localhost:8020/")
        .header(Authorization("Bearer ".to_string() + token_map.get("access_token").unwrap()))
        .build()
        .unwrap();
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

    HttpResponse::Ok()
        .content_type("text/html")
        .body(display_page)
        .unwrap()
}
