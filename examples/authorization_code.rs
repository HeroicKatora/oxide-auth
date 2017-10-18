#[cfg(feature = "iron-backend")]
mod main {
    extern crate oauth2_server;
    extern crate iron;
    extern crate router;
    extern crate url;
    extern crate reqwest;
    use self::iron::prelude::*;
    use self::oauth2_server::iron::{IronGranter, AuthenticationRequest, Authentication, ExpectAuthenticationHandler};
    use self::oauth2_server::code_grant::authorizer::Storage;
    use self::oauth2_server::code_grant::issuer::TokenMap;
    use self::oauth2_server::code_grant::generator::RandomGenerator;
    use self::oauth2_server::code_grant::QueryMap;
    use std::collections::HashMap;

    pub fn exec() {
        let ohandler = IronGranter::new({
            let mut storage = Storage::new(RandomGenerator::new(16));
            storage.register_client("myself", url::Url::parse("http://localhost:8020/my_endpoint").unwrap());
            storage
        }, TokenMap::new(RandomGenerator::new(32)));

        let mut router = router::Router::new();
        router.get("/authorize", ohandler.authorize(Box::new(owner_handler)), "authorize");
        router.any("/my_endpoint", dummy_client, "client");
        router.post("/token", ohandler.token(), "token");

        iron::Iron::new(router).http("localhost:8020").unwrap();

        fn owner_handler(req: &mut Request) -> IronResult<Response> {
            match req.method {
                iron::method::Method::Get => {
                    let (client_id, scope) = match req.extensions.get::<AuthenticationRequest>() {
                        None => return Ok(Response::with((iron::status::InternalServerError, "Expected to be invoked as oauth authentication"))),
                        Some(req) => (req.client_id.clone(), req.scope.clone()),
                    };

                    req.extensions.insert::<Authentication>(Authentication::InProgress);
                    let text = format!("{} is requesting permission for {}", client_id, scope);
                    Ok(Response::with((iron::status::Ok, text)))
                },
                iron::method::Method::Post => {
                    req.extensions.insert::<Authentication>(Authentication::Authenticated("dummy user".to_string()));
                    Err(IronError::new(ExpectAuthenticationHandler, ExpectAuthenticationHandler))
                },
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
        params.insert("redirect_url", "http://localhost:8020/my_endpoint");
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
