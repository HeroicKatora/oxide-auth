#[cfg(feature = "iron-backend")]
mod main {
    extern crate oauth2_server;
    extern crate iron;
    extern crate router;
    extern crate url;
    use self::oauth2_server::code_grant::iron::IronGranter;
    use self::oauth2_server::code_grant::authorizer::Storage;

    pub fn exec() {
        let ohandler = IronGranter::new({
            let mut storage = Storage::new();
            storage.register_client("myself", url::Url::parse("http://localhost:8020/my_endpoint").unwrap());
            storage
        });

        let mut router = router::Router::new();
        router.get("/authorize", ohandler.authorize(), "authorize");
        router.get("/my_endpoint", client, "client");

        iron::Iron::new(router).http("localhost:8020").unwrap();

        fn client(_req: &mut iron::Request) -> iron::IronResult<iron::Response> {
            Ok(iron::Response::with((iron::status::Ok, "Processing oauth request")))
        }
    }
}

#[cfg(not(feature = "iron-backend"))]
mod main { pub fn exec() { } }

fn main() {
    main::exec();
}
