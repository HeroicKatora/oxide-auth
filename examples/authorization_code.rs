#[cfg(feature = "iron-backend")]
mod main {
    extern crate oauth2_server;
    extern crate iron;
    extern crate router;
    extern crate url;
    extern crate reqwest;
    use self::oauth2_server::iron::IronGranter;
    use self::oauth2_server::code_grant::authorizer::Storage;

    pub fn exec() {
        let ohandler = IronGranter::new({
            let mut storage = Storage::new();
            storage.register_client("myself", url::Url::parse("http://localhost:8020/my_endpoint").unwrap());
            storage
        });

        let mut router = router::Router::new();
        router.get("/authorize", ohandler.authorize(), "authorize");
        router.any("/my_endpoint", client, "client");
        router.post("/token", ohandler.token(), "token");

        iron::Iron::new(router).http("localhost:8020").unwrap();

        fn client(_req: &mut iron::Request) -> iron::IronResult<iron::Response> {
            use std::io::Read;
            let client = reqwest::Client::new();
            let mut token_req = match client.post("http://localhost:8020/token").send() {
                Err(_) => return Ok(iron::Response::with((iron::status::InternalServerError, "Error retrieving token from server"))),
                Ok(v) => v
            };
            let mut token = String::new();
            token_req.read_to_string(&mut token).unwrap();
            Ok(iron::Response::with((iron::status::Ok, token)))
        }
    }
}

#[cfg(not(feature = "iron-backend"))]
mod main { pub fn exec() { } }

fn main() {
    main::exec();
}
