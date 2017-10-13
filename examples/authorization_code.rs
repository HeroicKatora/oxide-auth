extern crate oauth2_server;
extern crate iron;
use oauth2_server::code_grant::iron::IronGranter;
use oauth2_server::code_grant::authorizer::Storage;

fn main() {
    let ohandler = IronGranter::new({
        let mut storage = Storage::new();
        storage.register_client("myself", iron::Url::parse("http://localhost:8020/client_endpoint").unwrap());
        storage
    });

    iron::Iron::new(ohandler).http("localhost:8020").unwrap();
}
