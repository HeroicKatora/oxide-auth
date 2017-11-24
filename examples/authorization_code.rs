#[cfg(feature = "iron-backend")]
mod main {
    extern crate oxide_auth;
    extern crate iron;
    extern crate router;
    extern crate url;
    extern crate reqwest;
    extern crate serde;
    extern crate serde_json;
    extern crate urlencoded;
    use self::iron::prelude::*;
    use self::oxide_auth::iron::prelude::*;
    use self::urlencoded::UrlEncodedQuery;
    use std::collections::HashMap;
    use std::thread;

    /// Example of a main function of a iron server supporting oauth.
    pub fn example() {
        let passphrase = "This is a super secret phrase";

        // Create the main token instance, a code_granter with an iron frontend.
        let ohandler = IronGranter::new(
            // Stores clients in a simple in-memory hash map.
            ClientMap::new(),
            // Authorization tokens are 16 byte random keys to a memory hash map.
            Storage::new(RandomGenerator::new(16)),
            // Bearer tokens are signed (but not encrypted) using a passphrase.
            TokenSigner::new_from_passphrase(passphrase));

        // Register a dummy client instance
        ohandler.registrar().unwrap().register_client("LocalClient", url::Url::parse("http://localhost:8021/endpoint").unwrap());

        // Create a router and bind the relevant pages
        let mut router = router::Router::new();
        let mut protected = iron::Chain::new(|_: &mut Request| {
            Ok(Response::with((iron::status::Ok, "Hello World!")))
        });
        protected.link_before(ohandler.guard(vec!["default".parse::<Scope>().unwrap()]));
        protected.link_after(HelpfulAuthorizationError());
        router.get("/authorize", ohandler.authorize(handle_get), "authorize");
        router.post("/authorize", ohandler.authorize(IronOwnerAuthorizer(handle_post)), "authorize");
        router.post("/token", ohandler.token(), "token");
        router.get("/", protected, "protected");

        // Start the server
        let join = thread::spawn(|| iron::Iron::new(router).http("localhost:8020").unwrap());
        // Start a dummy client instance which simply relays the token/response
        let client = thread::spawn(|| iron::Iron::new(dummy_client).http("localhost:8021").unwrap());

        // Try to direct the browser to an url initiating the flow
        open_in_browser();
        join.join().expect("Failed to run");
        client.join().expect("Failed to run client");

        /// A simple implementation of the first part of an authentication handler. This will
        /// display a page to the user asking for his permission to proceed. The submitted form
        /// will then trigger the other authorization handler which actually completes the flow.
        fn handle_get(_: &mut Request, auth: AuthenticationRequest) -> Result<(Authentication, Response), OAuthError> {
            let (client_id, scope) = (auth.client_id, auth.scope);
            let text = format!(
                "<html>'{}' is requesting permission for '{}'
                <form action=\"authorize?response_type=code&client_id={}&redirect_url=http://localhost:8021/endpoint\" method=\"post\">
                    <input type=\"submit\" value=\"Accept\">
                </form>
                <form action=\"authorize?response_type=code&client_id={}&redirect_url=http://localhost:8021/endpoint&deny=1\" method=\"post\">
                    <input type=\"submit\" value=\"Deny\">
                </form>
                </html>", client_id, scope, client_id, client_id);
            let response = Response::with((iron::status::Ok, iron::modifiers::Header(iron::headers::ContentType::html()), text));
            Ok((Authentication::InProgress, response))
        }

        /// This shows the second style of authentication handler, a iron::Handler compatible form.
        /// Allows composition with other libraries or frameworks built around iron.
        fn handle_post(req: &mut Request) -> IronResult<Response> {
            // No real user authentication is done here, in production you SHOULD use session keys or equivalent
            if req.get::<UrlEncodedQuery>().unwrap_or(HashMap::new()).contains_key("deny") {
                req.extensions.insert::<Authentication>(Authentication::Failed);
            } else {
                req.extensions.insert::<Authentication>(Authentication::Authenticated("dummy user".to_string()));
            }
            Ok(Response::with(iron::status::Ok))
        }
    }

    struct HelpfulAuthorizationError();

    impl iron::middleware::AfterMiddleware for HelpfulAuthorizationError {
        fn catch(&self, _: &mut Request, err: iron::IronError) -> IronResult<Response> {
            if !err.error.is::<OAuthError>() {
                return Err(err);
            }
            use main::iron::modifier::Modifier;
            let mut response = err.response;
            let text =
                "<html>
                This page should be accessed via an oauth token from the client in the example. Click
                <a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient&redirect_url=http://localhost:8021/endpoint\">
                here</a> to begin the authorization process.
                </html>";
            text.modify(&mut response);
            iron::modifiers::Header(iron::headers::ContentType::html()).modify(&mut response);
            Ok(response)
        }
    }

    fn open_in_browser() {
        let target_addres = "http://localhost:8020/";
        use std::io::{Error, ErrorKind};
        use std::process::Command;
        let can_open = if cfg!(target_os = "linux") {
            Ok("x-www-browser")
        } else {
            Err(Error::new(ErrorKind::Other, "Open not supported"))
        };
        can_open.and_then(|cmd| Command::new(cmd).arg(target_addres).status())
            .and_then(|status| if status.success() { Ok(()) } else { Err(Error::new(ErrorKind::Other, "Non zero status")) })
            .unwrap_or_else(|_| println!("Please navigate to {}", target_addres));
    }

    /// Rough client function mirroring core functionality of an oauth client. This is not actually
    /// needed in your implementation but merely exists to provide an interactive example.
    fn dummy_client(req: &mut iron::Request) -> iron::IronResult<iron::Response> {
        use std::io::Read;
        use main::serde::ser::Serialize;
        // Check the received parameters in the input
        let query = req.url.as_ref().query_pairs().collect::<HashMap<_, _>>();
        if let Some(error) = query.get("error") {
            let message = "Error during owner authorization: ".to_string() + error.as_ref();
            return Ok(iron::Response::with((iron::status::Ok, message)));
        };
        let code = match query.get("code") {
            None => return Ok(iron::Response::with((iron::status::BadRequest, "Missing code"))),
            Some(v) => v.clone()
        };

        // Construct a request against http://localhost:8020/token, the access token endpoint
        let client = reqwest::Client::new();
        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("client_id", "LocalClient");
        params.insert("code", &code);
        params.insert("redirect_url", "http://localhost:8021/endpoint");
        let access_token_request = client
            .post("http://localhost:8020/token")
            .form(&params).build().unwrap();
        let mut token_response = client.execute(access_token_request).unwrap();
        let mut token = String::new();
        token_response.read_to_string(&mut token).unwrap();
        let token_map: HashMap<String, String> = serde_json::from_str(&token).unwrap();

        if token_map.get("error").is_some() || !token_map.get("access_token").is_some() {
            return Ok(iron::Response::with((iron::status::BadRequest, token)));
        }

        // Request the page with the oauth token
        let page_request = client
            .get("http://localhost:8020/")
            .header(reqwest::header::Authorization("Bearer ".to_string() + token_map.get("access_token").unwrap()))
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
            iron::status::Ok,
            iron::modifiers::Header(iron::headers::ContentType::html()),
            display_page,
        )))
    }
}

#[cfg(not(feature = "iron-backend"))]
mod main { pub fn example() { } }

fn main() {
    main::example();
}
