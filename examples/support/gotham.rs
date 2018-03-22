extern crate reqwest;
extern crate gotham;
extern crate mime;
extern crate serde_urlencoded;
extern crate serde;
extern crate serde_json;
extern crate hyper;

use self::reqwest::header::Authorization;
use self::hyper::{StatusCode, Request, Response};
use self::gotham::state::{FromState, State};
use self::gotham::http::response::create_response;
use self::gotham::router::Router;
use self::gotham::router::builder::*;
use self::gotham::router::response::extender::StaticResponseExtender;

use std::collections::HashMap;
use std::io::Read;

#[derive(Deserialize, StateData, StaticResponseExtender)]
pub struct QueryStringExtractor {
    error: Option<String>,
    code: Option<String>,
}

pub fn dummy_client(mut state: State) -> (State, Response) {
    let query_params = QueryStringExtractor::take_from(&mut state);
    if let Some(cause) = query_params.error {
        let res = create_response(
            &state,
            StatusCode::Ok,
            Some((format!("Error during owner authorization: {:?}", cause).into_bytes(), mime::TEXT_PLAIN)),
        );
        return (state, res);
    }

    let code = match query_params.code {
        None => {
          let res = create_response(
            &state,
            StatusCode::BadRequest,
            Some((String::from("Missing code").into_bytes(), mime::TEXT_PLAIN)),
          );
          return (state, res)
        },
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
        let res = create_response(&state, StatusCode::BadRequest, Some((token.into_bytes(), mime::TEXT_PLAIN)));
        return (state, res);
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

    let res = create_response(
        &state,
        StatusCode::Ok,
        Some((display_page.into_bytes(), mime::TEXT_HTML)),
    );

    (state, res)
}
