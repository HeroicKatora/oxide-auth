use std::collections::HashMap;

use primitives::authorizer::{Authorizer, Storage};
use primitives::generator::RandomGenerator;
use primitives::issuer::{Issuer, TokenSigner};
use primitives::registrar::{Client, ClientMap};
use primitives::scope::Scope;
use primitives::grant::{Extensions, Grant};

use code_grant::endpoint::{PreGrant, OAuthError, OwnerConsent};
use frontends::simple::endpoint::FnSolicitor;
use frontends::simple::request::{Body, MapErr, NoError, Request, Response, Status};

use super::{AsActor, access_token, authorization, resource};
use super::actix::{Actor, Addr, System, SystemRunner};

use chrono::{Utc, Duration};
use url::Url;
use serde_json;

struct Setup {
    authorizer: Addr<AsActor<Storage<RandomGenerator>>>,
    registrar: Addr<AsActor<ClientMap>>,
    issuer: Addr<AsActor<TokenSigner>>,
    runner: SystemRunner,
    valid_authorization: String,
    valid_token: String,
}

impl Setup {
    fn start() -> Self {
        use self::defaults::*;

        let scope = EXAMPLE_SCOPE.parse().unwrap();

        let mut authorizer = Storage::new(RandomGenerator::new(16));
        let mut registrar = ClientMap::new();
        let mut issuer = TokenSigner::ephemeral();

        registrar.register_client(Client::confidential(
            EXAMPLE_CLIENT_ID,
            EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope,
            EXAMPLE_PASSPHRASE.as_bytes(),
        ));

        let grant = Grant {
            client_id: EXAMPLE_CLIENT_ID.to_string(),
            owner_id: EXAMPLE_OWNER_ID.to_string(),
            redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope: EXAMPLE_SCOPE.parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        };

        let valid_authorization = authorizer.authorize(grant.clone()).unwrap();
        let valid_token = issuer.issue(grant).unwrap().token;

        let runner = System::new("OAuthTestSystem");
        let authorizer = AsActor(authorizer).start();
        let registrar = AsActor(registrar).start();
        let issuer = AsActor(issuer).start();

        Setup {
            authorizer,
            registrar,
            issuer,
            runner,
            valid_authorization,
            valid_token,
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

#[test]
fn future_access_token() {
    let mut setup = Setup::start();

    let request = Request {
        query: HashMap::new(),
        urlbody: vec![
            ("grant_type", "authorization_code"),
            ("code", &setup.valid_authorization),
            ("redirect_uri", defaults::EXAMPLE_REDIRECT_URI)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        auth: Some("Basic ".to_string() + &base64::encode(&format!("{}:{}",
            defaults::EXAMPLE_CLIENT_ID, defaults::EXAMPLE_PASSPHRASE))),
    };

    let response = Response::default();

    let result = setup.runner.block_on(access_token(
        setup.registrar.clone(),
        setup.authorizer.clone(),
        setup.issuer.clone(),
        MapErr::request(request, NoError::into::<OAuthError>),
        MapErr::response(response, NoError::into::<OAuthError>)));

    let result = result
        .expect("Should not be an actix error");
    let response = result
        .expect("Should not be an oauth error");
    let response = response.into_inner();

    assert_eq!(response.status, Status::Ok);

    let body = response.body.as_ref().map(Body::as_str)
        .expect("Should have a body");
    let response = serde_json::from_str::<HashMap<String, String>>(body)
        .expect("Should decode as valid json map");

    assert!(response.get("access_token").is_some());
    assert_eq!(response.get("token_type").cloned(), Some("bearer".to_owned()));
}

#[test]
fn future_resource() {
    let mut setup = Setup::start();

    let request = Request {
        query: HashMap::new(),
        urlbody: HashMap::new(),
        auth: Some("Bearer ".to_string() + &setup.valid_token),
    };

    let response = Response::default();

    let result = setup.runner.block_on(resource(
        setup.issuer.clone(),
        vec![defaults::EXAMPLE_SCOPE.parse().unwrap()],
        MapErr::request(request, NoError::into::<OAuthError>),
        MapErr::response(response, NoError::into::<OAuthError>)));

    let result = result
        .expect("Should not be an actix error");

    let () = match result {
        Ok(()) => (),
        Err(Err(err)) => panic!("Should not be an oauth error: {:?}", err),
        Err(Ok(resp)) => panic!("Should not be a response: {:?}", resp.into_inner()),
    };
}
