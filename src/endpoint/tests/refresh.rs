use primitives::issuer::{Issuer, IssuedToken, RefreshedToken, TokenMap};
use primitives::generator::RandomGenerator;
use primitives::grant::{Grant, Extensions};
use primitives::registrar::{Client, ClientMap};

use std::collections::HashMap;

use base64;
use chrono::{Utc, Duration};
use serde_json;

use super::{Body, CraftedRequest, Status, ToSingleValueQuery};
use super::defaults::*;
use frontends::simple::endpoint::{refresh_flow, resource_flow};

struct AccessTokenSetup {
    registrar: ClientMap,
    issuer: TokenMap<RandomGenerator>,
    issued: IssuedToken,
    basic_authorization: String,
}

impl AccessTokenSetup {
    const SMALLER_SCOPE: &'static str = "example";
    const WIDER_SCOPE: &'static str = "example default more";
    const DISJUNCT_SCOPE: &'static str = "example more";

    fn private_client() -> Self {
        let mut registrar = ClientMap::new();
        let mut issuer = TokenMap::new(RandomGenerator::new(16));

        let client = Client::confidential(EXAMPLE_CLIENT_ID,
            EXAMPLE_REDIRECT_URI.parse().unwrap(),
            EXAMPLE_SCOPE.parse().unwrap(),
            EXAMPLE_PASSPHRASE.as_bytes());

        let grant = Grant {
            client_id: EXAMPLE_CLIENT_ID.to_string(),
            owner_id: EXAMPLE_OWNER_ID.to_string(),
            redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope: EXAMPLE_SCOPE.parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        };

        registrar.register_client(client);
        let issued = issuer.issue(grant).unwrap();
        assert!(!issued.refresh.is_empty());

        let basic_authorization = base64::encode(&format!("{}:{}",
            EXAMPLE_CLIENT_ID, EXAMPLE_PASSPHRASE));
        let basic_authorization = format!("Basic {}", basic_authorization);

        AccessTokenSetup {
            registrar,
            issuer,
            issued,
            basic_authorization,
        }
    }

    fn public_client() -> Self {
        let mut registrar = ClientMap::new();
        let mut issuer = TokenMap::new(RandomGenerator::new(16));

        let client = Client::public(EXAMPLE_CLIENT_ID,
            EXAMPLE_REDIRECT_URI.parse().unwrap(),
            EXAMPLE_SCOPE.parse().unwrap());

        let grant = Grant {
            client_id: EXAMPLE_CLIENT_ID.to_string(),
            owner_id: EXAMPLE_OWNER_ID.to_string(),
            redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope: EXAMPLE_SCOPE.parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        };

        registrar.register_client(client);
        let issued = issuer.issue(grant).unwrap();
        assert!(!issued.refresh.is_empty());

        let basic_authorization = "DO_NOT_USE".into();

        AccessTokenSetup {
            registrar,
            issuer,
            issued,
            basic_authorization,
        }
    }

    fn test_success(&mut self, request: CraftedRequest) -> RefreshedToken {
        let response = refresh_flow(&self.registrar, &mut self.issuer)
            .execute(request)
            .expect("Expected non-error reponse");
        assert_eq!(response.status, Status::Ok);
        let body = match response.body {
            Some(Body::Json(body)) => body,
            _ => panic!("Expect json body"),
        };
        let mut body: HashMap<String, String> = serde_json::from_str(&body)
            .expect("Expected valid json body");
        let duration: i64 = body.remove("expires_in")
            .unwrap()
            .parse()
            .unwrap();
        RefreshedToken {
            token: body.remove("access_token").expect("Expected a token"),
            refresh: body.remove("refresh_token"),
            until: Utc::now() + Duration::seconds(duration),
        }
    }

    fn access_resource(&mut self, token: String) {
        let request = CraftedRequest {
            query: None,
            urlbody: None,
            auth: Some(format!("Bearer {}", token)),
        };

        resource_flow(&mut self.issuer, &[EXAMPLE_SCOPE.parse().unwrap()])
            .execute(request)
            .expect("Expected access allowed");
    }
}

#[test]
fn access_valid_public() {
    let mut setup = AccessTokenSetup::public_client();

    let valid_public = CraftedRequest {
        query: None,
        urlbody: Some(vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", &setup.issued.refresh)]
            .iter().to_single_value_query()),
        auth: None,
    };

    let new_token = setup.test_success(valid_public);
    setup.access_resource(new_token.token);
}

#[test]
fn access_valid_private() {
    let mut setup = AccessTokenSetup::private_client();

    let valid_public = CraftedRequest {
        query: None,
        urlbody: Some(vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", &setup.issued.refresh)]
            .iter().to_single_value_query()),
        auth: Some(setup.basic_authorization.clone()),
    };

    let new_token = setup.test_success(valid_public);
    setup.access_resource(new_token.token);
}
