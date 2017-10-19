#[cfg(feature = "iron-backend")]
mod main {
    extern crate oauth2_server;
    extern crate iron;
    extern crate router;
    extern crate url;
    extern crate reqwest;
    use self::iron::prelude::*;
    use self::oauth2_server::iron::{IronGranter, AuthenticationRequest, Authentication, ExpectAuthenticationHandler};
    use self::oauth2_server::code_grant::prelude::*;
    use std::collections::HashMap;
    use std::thread;

    pub fn exec() {
        let ohandler = IronGranter::new(
            Storage::new(RandomGenerator::new(16)),
            TokenMap::new(RandomGenerator::new(32)));
        ohandler.authorizer().unwrap().register_client("myself", url::Url::parse("http://localhost:8021/endpoint").unwrap());

        let mut router = router::Router::new();
        router.any("/authorize", ohandler.authorize(Box::new(owner_handler)), "authorize");
        router.post("/token", ohandler.token(), "token");

        let join = thread::spawn(|| iron::Iron::new(router).http("localhost:8020").unwrap());
        let client = thread::spawn(|| iron::Iron::new(dummy_client).http("localhost:8021").unwrap());

        let target_addres = "localhost:8020/authorize?response_type=code&client_id=myself";
        use std::io::{Error, ErrorKind};
        use std::process::Command;
        let can_open = if cfg!(target_os = "linux") { Ok("x-www-browser") } else { Err(Error::new(ErrorKind::Other, "Open not supported")) };
        can_open.and_then(|cmd| Command::new(cmd).arg(target_addres).status())
            .and_then(|status| { if status.success() { Ok(()) } else { Err(Error::new(ErrorKind::Other, "Non zero status")) } })
            .unwrap_or_else(|_| println!("Please navigate to {}", target_addres));

        join.join().expect("Failed to run");
        client.join().expect("Failed to run client");

        fn handle_get(req: &mut Request) -> IronResult<Response> {
            let (client_id, scope) = match req.extensions.get::<AuthenticationRequest>() {
                None => return Ok(Response::with((iron::status::InternalServerError, "Expected to be invoked as oauth authentication"))),
                Some(req) => (req.client_id.clone(), req.scope.clone()),
            };

            req.extensions.insert::<Authentication>(Authentication::InProgress);
            let text = format!("<html>{} is requesting permission for {}
                <form action=\"authorize?response_type=code&client_id={}\" method=\"post\">
                    <input type=\"submit\" value=\"Accept\">
                </form></html>", client_id, scope, client_id);
            Ok(Response::with((iron::status::Ok, iron::modifiers::Header(iron::headers::ContentType::html()), text)))
        }

        fn handle_post(req: &mut Request) -> IronResult<Response> {
            req.extensions.insert::<Authentication>(Authentication::Authenticated("dummy user".to_string()));
            Err(IronError::new(ExpectAuthenticationHandler, ExpectAuthenticationHandler))
        }

        fn owner_handler(req: &mut Request) -> IronResult<Response> {
            match req.method {
                iron::method::Method::Get => handle_get(req),
                iron::method::Method::Post => handle_post(req),
                _ => {
                    return Ok(Response::with((iron::status::BadRequest, "Only accessible via get and post")))
                }
            }
        }
    }

    fn dummy_client(req: &mut iron::Request) -> iron::IronResult<iron::Response> {
        use std::io::Read;
        let code = match req.url.as_ref().query_pairs().collect::<QueryMap>().get("code") {
            None => return Ok(iron::Response::with((iron::status::BadRequest, "Missing code"))),
            Some(v) => v.clone()
        };

        let client = reqwest::Client::new();
        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("client_id", "myself");
        params.insert("code", &code);
        params.insert("redirect_url", "http://localhost:8021/endpoint");
        let constructed_req = client
            .post("http://localhost:8020/token")
            .form(&params).build().unwrap();
        let mut token_req = match client.execute(constructed_req) {
            Err(_) => return Ok(iron::Response::with((iron::status::InternalServerError, "Error retrieving token from server"))),
            Ok(v) => v
        };
        let mut token = String::new();
        token_req.read_to_string(&mut token).unwrap();
        Ok(iron::Response::with((iron::status::Ok, format!("Received token: {}", token))))
    }
}

#[cfg(not(feature = "iron-backend"))]
mod main { pub fn exec() { } }

fn main() {
    main::exec();
}
