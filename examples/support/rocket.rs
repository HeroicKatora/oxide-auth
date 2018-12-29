extern crate reqwest;
extern crate rocket;
extern crate serde_urlencoded;
extern crate serde;
extern crate serde_json;

use self::reqwest::header;
use rocket::{Request, Response, Rocket, State};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::{ContentType, Status};
use rocket::response::Redirect;
use rocket::response::content::Html;
use rocket::response::status::Custom;
use rocket::request::{self, FromRequest, Outcome};

use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::{Mutex, MutexGuard};

pub struct ClientFairing;

impl Fairing for ClientFairing {
    fn info(&self) -> Info {
        Info {
            name: "Simple oauth client implementation",
            kind: Kind::Attach,
        }
    }

    fn on_attach(&self, rocket: Rocket) -> Result<Rocket, Rocket> {
        Ok(rocket
            .manage(ClientState {
                token: Mutex::new(None),
            })
            .mount("/clientside", routes![oauth_endpoint, client_view, client_debug]))
    }
}

struct ClientState {
    token: Mutex<Option<String>>,
}

struct Token<'r> {
    inner: MutexGuard<'r, Option<String>>,
}

#[get("/endpoint?<code>&<error>")]
fn oauth_endpoint<'r>(code: Option<String>, error: Option<String>, mut guard: Token<'r>)
    -> Result<Redirect, String> 
{
    if let Some(error) = error {
        return Err(format!("Error during owner authorization: {:?}", error))
    }
    if let Some(code) = code {
        let token = retrieve_token(code)?;
        *guard.inner = Some(token);
        return Ok(Redirect::found("/clientside"))
    }

    Err(format!("Endpoint hit without an authorization code"))
}

#[get("/")]
fn client_view<'r>(guard: Token<'r>) -> Result<Html<String>, Custom<&'static str>> {
    let token = match *guard.inner {
        Some(ref token) => token,
        None => return Err(Custom(Status::PreconditionFailed, "No token retrieved yet")),
    };

    let protected_page = retrieve_protected_page(token)
        .unwrap_or_else(|err| format!("Error: {}", err));
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
        <article>{:?}</article>
        </main></html>", token, protected_page);

    Ok(Html(display_page))
}

#[get("/debug")]
fn client_debug<'r>(guard: Token<'r>) -> String {
    match *guard.inner {
        Some(ref token) => token.to_owned(),
        None => "".to_owned(),
    }
}

fn retrieve_token(code: String) -> Result<String, String> {
    // Construct a request against http://localhost:8020/token, the access token endpoint
    let client = reqwest::Client::new();

    let mut params = HashMap::new();
    params.insert("grant_type", "authorization_code");
    params.insert("client_id", "LocalClient");
    params.insert("code", &code);
    params.insert("redirect_uri", "http://localhost:8000/clientside/endpoint");
    let access_token_request = client
        .post("http://localhost:8000/token")
        .form(&params).build().unwrap();
    let mut token_response = match client.execute(access_token_request) {
        Ok(response) => response,
        Err(_) => return Err("Could not fetch bearer token".into()),
    };

    let mut token = String::new();
    token_response.read_to_string(&mut token).unwrap();
    let token_map: HashMap<String, String> = match serde_json::from_str(&token) {
        Ok(token_map) => token_map,
        Err(err) => return Err(format!("Error unwrapping json response, got {:?} instead", err)),
    };

    if let Some(err) = token_map.get("error") {
        return Err(format!("Error fetching bearer token: {:?}", err))
    }

    if let Some(token) = token_map.get("access_token") {
        return Ok(token.to_owned())
    }

    Err("Token response neither error nor token".into())
}

fn retrieve_protected_page(token: &str) -> Result<String, String> {
    let client = reqwest::Client::new();

    // Request the page with the oauth token
    let page_request = client
        .get("http://localhost:8000/")
        .header(header::AUTHORIZATION, "Bearer ".to_string() + token)
        .build()
        .unwrap();

    let mut page_response = match client.execute(page_request) {
        Ok(response) => response,
        Err(_) => return Err("Could not access protected resource".into()),
    };

    let mut protected_page = String::new();
    page_response.read_to_string(&mut protected_page).unwrap();
    Ok(protected_page)
}

impl<'a, 'r> FromRequest<'a, 'r> for Token<'r> {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        request.guard::<State<'r, ClientState>>()
            .map(|ok| Token { inner: ok.inner().token.lock().unwrap(), })
    }
}
