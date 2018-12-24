use std::collections::HashMap;

use primitives::authorizer::Storage;
use primitives::generator::RandomGenerator;
use primitives::issuer::Issuer;
use primitives::registrar::{Client, ClientMap};
use primitives::scope::Scope;

use code_grant::endpoint::{PreGrant, OAuthError, OwnerConsent};
use frontends::simple::endpoint::FnSolicitor;
use frontends::simple::request::{MapErr, NoError, Request, Response, Status};

use super::{AsActor, authorization};
use super::actix::{Actor, Addr, System, SystemRunner};

use url::Url;

struct Setup {
    authorizer: Addr<AsActor<Storage<RandomGenerator>>>,
    registrar: Addr<AsActor<ClientMap>>,
    runner: SystemRunner,
}

impl Setup {
    fn start() -> Self {
        use self::defaults::*;

        let scope = EXAMPLE_SCOPE.parse().unwrap();

        let authorizer = Storage::new(RandomGenerator::new(16));
        let mut registrar = ClientMap::new();

        registrar.register_client(Client::public(
            EXAMPLE_CLIENT_ID,
            EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope,
        ));

        let runner = System::new("OAuthTestSystem");
        let authorizer = AsActor(authorizer).start();
        let registrar = AsActor(registrar).start();

        Setup {
            authorizer,
            registrar,
            runner,
        }
    }
}

mod defaults {
    pub const EXAMPLE_CLIENT_ID: &str = "ClientId";
    pub const EXAMPLE_OWNER_ID: &str = "Owner";
    pub const EXAMPLE_PASSPHRASE: &str = "VGhpcyBpcyBhIHZlcnkgc2VjdXJlIHBhc3NwaHJhc2UK";
    pub const EXAMPLE_REDIRECT_URI: &str = "https://client.example/endpoint";
    pub const EXAMPLE_SCOPE: &str = "example default";
}

#[test]
fn future_authorization() {
    let mut setup = Setup::start();

    let request = Request {
        query: vec![
            ("response_type", "code"),
            ("client_id", defaults::EXAMPLE_CLIENT_ID),
            ("redirect_uri", defaults::EXAMPLE_REDIRECT_URI)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        urlbody: HashMap::new(),
        auth: None,
    };

    let response = Response::default();

    let result = setup.runner.block_on(authorization(
        setup.registrar.clone(),
        setup.authorizer.clone(),
        FnSolicitor(|_req: &mut _, _: &_| { OwnerConsent::Authorized(defaults::EXAMPLE_OWNER_ID.to_string()) }),
        MapErr::request(request, NoError::into::<OAuthError>),
        MapErr::response(response, NoError::into::<OAuthError>)));

    let result = result
        .expect("Should not be an actix error");
    let response = result
        .expect("Should not be an oauth error");
    let response = response.into_inner();

    assert_eq!(response.status, Status::Redirect);

    let location = response.location.expect("Location header should be set");
    eprintln!("{:?}", &location);
    assert_eq!(location.as_str().find("error"), None);
}
