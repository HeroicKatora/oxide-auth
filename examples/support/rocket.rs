extern crate rocket;

#[path = "generic.rs"]
mod generic;

use self::generic::{Client, ClientConfig, ClientError};

use rocket::{Rocket, State, Build};
use rocket::fairing::{Fairing, Info, Kind, Result};
use rocket::http::Status;
use rocket::response::{Redirect, content::Html, status::Custom};

pub use self::generic::consent_page_html;
pub struct ClientFairing;

#[rocket::async_trait]
impl Fairing for ClientFairing {
    fn info(&self) -> Info {
        Info {
            name: "Simple oauth client implementation",
            kind: Kind::Ignite,
        }
    }

    async fn on_ignite(&self, rocket: Rocket<Build>) -> Result {
        let config = ClientConfig {
            client_id: "LocalClient".into(),
            protected_url: "http://localhost:8000/".into(),
            token_url: "http://localhost:8000/token".into(),
            refresh_url: "http://localhost:8000/refresh".into(),
            redirect_uri: "http://localhost:8000/clientside/endpoint".into(),
            client_secret: None
        };
        Ok(rocket
            .manage(Client::new(config))
            .mount("/clientside", routes![oauth_endpoint, client_view, client_debug, refresh]))
    }
}

#[get("/endpoint?<code>&<error>")]
fn oauth_endpoint<'r>(code: Option<String>, error: Option<String>, state: &State<Client>)
    -> Result<Redirect, Custom<String>> 
{
    if let Some(error) = error {
        return Err(Custom(Status::InternalServerError, 
            format!("Error during owner authorization: {:?}", error)))
    }

    let code = code
        .ok_or_else(|| Custom(Status::BadRequest, 
            "Endpoint hit without an authorization code".into()))?;

    state.authorize(&code)
        .map_err(internal_error)?;

    Ok(Redirect::found("/clientside"))
}

#[get("/")]
fn client_view(state: &State<Client>) -> Result<Html<String>, Custom<String>> {
    let protected_page = state
        .retrieve_protected_page()
        .map_err(internal_error)?;

    let display_page = format!(
        "<html><style>
            aside{{overflow: auto; word-break: keep-all; white-space: nowrap}}
            main{{text-align: center}}
            main>aside,main>article{{margin: auto; text-align: left; border: 1px solid black; width: 50%}}
        </style>
        <main>
        Used token <aside style>{}</aside> to access
        <a href=\"http://localhost:8000/\">http://localhost:8000/</a>.
        Its contents are:
        <article>{:?}</article>
        <form action=\"/clientside/refresh\" method=\"post\"><button>Refresh token</button></form>
        </main></html>", state.as_html(), protected_page);

    Ok(Html(display_page))
}

#[post("/refresh")]
fn refresh(state: &State<Client>) -> Result<Redirect, Custom<String>> {
    state.refresh()
        .map_err(internal_error)
        .map(|()| Redirect::found("/clientside"))
}

#[get("/debug")]
fn client_debug(state: &State<Client>) -> Html<String> {
    Html(state.as_html())
}

fn internal_error(err: ClientError) -> Custom<String> {
    Custom(Status::InternalServerError, err.to_string())
}
