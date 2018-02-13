use primitives::authorizer::Storage;
use primitives::issuer::TokenMap;
use primitives::grant::{Grant, Extensions};
use primitives::registrar::{Client, ClientMap};

use code_grant::frontend::GrantFlow;

use std::collections::HashMap;

use base64;
use chrono::{Utc, Duration};
use serde_json;

use super::{CraftedRequest, CraftedResponse, TestGenerator, ToSingleValueQuery};
use super::defaults::*;


struct AccessTokenSetup {
    registrar: ClientMap,
    authorizer: Storage<TestGenerator>,
    issuer: TokenMap<TestGenerator>,
    authtoken: String,
    basic_authorization: String,
}

impl AccessTokenSetup {
    fn private_client() -> Self {
        use primitives::authorizer::Authorizer;
        let mut registrar = ClientMap::new();
        let mut authorizer = Storage::new(TestGenerator("AuthToken".to_string()));
        let issuer = TokenMap::new(TestGenerator("AccessToken".to_string()));

        let client = Client::confidential(EXAMPLE_CLIENT_ID,
            EXAMPLE_REDIRECT_URI.parse().unwrap(),
            EXAMPLE_SCOPE.parse().unwrap(),
            EXAMPLE_PASSPHRASE.as_bytes());

        let authrequest = Grant {
            client_id: EXAMPLE_CLIENT_ID.to_string(),
            owner_id: EXAMPLE_OWNER_ID.to_string(),
            redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope: EXAMPLE_SCOPE.parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        };

        let authtoken = authorizer.authorize(authrequest).unwrap();
        registrar.register_client(client);

        let basic_authorization = base64::encode(&format!("{}:{}",
            EXAMPLE_CLIENT_ID, EXAMPLE_PASSPHRASE));

        AccessTokenSetup {
            registrar,
            authorizer,
            issuer,
            authtoken,
            basic_authorization,
        }
    }

    fn public_client() -> Self {
        use primitives::authorizer::Authorizer;
        let mut registrar = ClientMap::new();
        let mut authorizer = Storage::new(TestGenerator("AuthToken".to_string()));
        let issuer = TokenMap::new(TestGenerator("AccessToken".to_string()));

        let client = Client::public(EXAMPLE_CLIENT_ID,
            EXAMPLE_REDIRECT_URI.parse().unwrap(),
            EXAMPLE_SCOPE.parse().unwrap());

        let authrequest = Grant {
            client_id: EXAMPLE_CLIENT_ID.to_string(),
            owner_id: EXAMPLE_OWNER_ID.to_string(),
            redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope: EXAMPLE_SCOPE.parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        };

        let authtoken = authorizer.authorize(authrequest).unwrap();
        registrar.register_client(client);

        let basic_authorization = base64::encode(&format!("{}:{}",
            EXAMPLE_CLIENT_ID, EXAMPLE_PASSPHRASE));

        AccessTokenSetup {
            registrar,
            authorizer,
            issuer,
            authtoken,
            basic_authorization,
        }
    }

    fn assert_json_error_set(response: &CraftedResponse) {
        match response {
            &CraftedResponse::Json(ref json) => {
                let content: HashMap<String, String> = serde_json::from_str(json).unwrap();
                assert!(content.get("error").is_some(), "Error not set in json response");
            },
            &CraftedResponse::Unauthorized(ref inner) => Self::assert_json_error_set(inner),
            &CraftedResponse::Authorization(ref inner, _) => Self::assert_json_error_set(inner),
            &CraftedResponse::ClientError(ref inner) => Self::assert_json_error_set(inner),
            _ => panic!("Expected json encoded body, got {:?}", response),
        }
    }

    fn test_simple_error(&mut self, mut request: CraftedRequest) {
        match GrantFlow::new(&self.registrar, &mut self.authorizer, &mut self.issuer)
            .handle(&mut request)
        {
            Ok(ref response) =>
                Self::assert_json_error_set(response),
            resp => panic!("Expected non-error reponse, got {:?}", resp),
        }
    }
}

#[test]
fn access_request_unknown_client() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to autenticate as some unknown client with the passphrase
    let unknown_client = CraftedRequest {
        query: None,
        urlbody: Some(vec![("grant_type", "authorization_code"),
                         ("code", &setup.authtoken),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI)]
            .iter().to_single_value_query()),
        auth: Some("Basic ".to_string() + &base64::encode(&format!("{}:{}",
            "SomeOtherClient", EXAMPLE_PASSPHRASE))),
    };

    setup.test_simple_error(unknown_client);
}

#[test]
fn access_request_wrong_authentication() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to autenticate with an unsupported method (instead of Basic)
    let wrong_authentication = CraftedRequest {
        query: None,
        urlbody: Some(vec![("grant_type", "authorization_code"),
                         ("code", &setup.authtoken),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI)]
            .iter().to_single_value_query()),
        auth: Some("NotBasic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(wrong_authentication);
}

#[test]
fn access_request_wrong_password() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to autenticate with the wrong password
    let wrong_password = CraftedRequest {
        query: None,
        urlbody: Some(vec![("grant_type", "authorization_code"),
                         ("code", &setup.authtoken),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI)]
            .iter().to_single_value_query()),
        auth: Some("Basic ".to_string() + &base64::encode(&format!("{}:{}",
            EXAMPLE_CLIENT_ID, "NotTheRightPassphrase"))),
    };

    setup.test_simple_error(wrong_password);
}

#[test]
fn access_request_empty_password() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to autenticate with an empty password
    let empty_password = CraftedRequest {
        query: None,
        urlbody: Some(vec![("grant_type", "authorization_code"),
                         ("code", &setup.authtoken),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI)]
            .iter().to_single_value_query()),
        auth: Some("Basic ".to_string() + &base64::encode(&format!("{}:{}",
            EXAMPLE_CLIENT_ID, ""))),
    };

    setup.test_simple_error(empty_password);
}

#[test]
fn access_request_multiple_client_indications() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to autenticate with an unsupported method (instead of Basic)
    let multiple_client_indications = CraftedRequest {
        query: None,
        urlbody: Some(vec![("grant_type", "authorization_code"),
                         ("client_id", EXAMPLE_CLIENT_ID),
                         ("code", &setup.authtoken),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI)]
            .iter().to_single_value_query()),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(multiple_client_indications);
}

#[test]
fn access_request_public_authorization() {
    let mut setup = AccessTokenSetup::public_client();
    // Trying to autenticate a public client
    let public_authorization = CraftedRequest {
        query: None,
        urlbody: Some(vec![("grant_type", "authorization_code"),
                         ("code", &setup.authtoken),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI)]
            .iter().to_single_value_query()),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(public_authorization);
}

#[test]
fn access_request_public_missing_client() {
    let mut setup = AccessTokenSetup::public_client();
    // Trying to autenticate with an unsupported method (instead of Basic)
    let public_missing_client = CraftedRequest {
        query: None,
        urlbody: Some(vec![("grant_type", "authorization_code"),
                         ("code", &setup.authtoken),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI)]
            .iter().to_single_value_query()),
        auth: None,
    };

    setup.test_simple_error(public_missing_client);
}


#[test]
fn access_request_invalid_basic() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to autenticate with an invalid basic authentication header
    let invalid_basic = CraftedRequest {
        query: None,
        urlbody: Some(vec![("grant_type", "authorization_code"),
                         ("code", &setup.authtoken),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI)]
            .iter().to_single_value_query()),
        auth: Some("Basic ;;;#Non-base64".to_string()),
    };

    setup.test_simple_error(invalid_basic);
}

#[test]
fn access_request_wrong_redirection() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to get an access token with an incorrect redirection url
    let wrong_redirection = CraftedRequest {
        query: None,
        urlbody: Some(vec![("grant_type", "authorization_code"),
                         ("code", &setup.authtoken),
                         ("redirect_uri", "https://wrong.client.example/endpoint")]
            .iter().to_single_value_query()),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(wrong_redirection);
}

#[test]
fn access_request_invalid_redirection() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to get an access token with a redirection url which is not an uri
    let invalid_redirection = CraftedRequest {
        query: None,
        urlbody: Some(vec![("grant_type", "authorization_code"),
                         ("code", &setup.authtoken),
                         ("redirect_uri", "\\://")]
            .iter().to_single_value_query()),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(invalid_redirection);
}

#[test]
fn access_request_no_code() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to get an access token without a code
    let no_code = CraftedRequest {
        query: None,
        urlbody: Some(vec![("grant_type", "authorization_code"),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI)]
            .iter().to_single_value_query()),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(no_code);
}

#[test]
fn access_request_multiple_codes() {
    let mut setup = AccessTokenSetup::private_client();
    let mut urlbody = vec![
            ("grant_type", "authorization_code"),
            ("code", &setup.authtoken),
            ("redirect_uri", EXAMPLE_REDIRECT_URI)]
        .iter().to_single_value_query();
    urlbody.get_mut("code").unwrap().push("AnotherAuthToken".to_string());
    // Trying to get an access token with mutiple codes, even if one is correct
    let multiple_codes = CraftedRequest {
        query: None,
        urlbody: Some(urlbody),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(multiple_codes);
}

#[test]
fn access_request_wrong_grant_type() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to get an access token without a code
    let wrong_grant_type = CraftedRequest {
        query: None,
        urlbody: Some(vec![("grant_type", "another_grant_type"),
                         ("code", &setup.authtoken),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI)]
            .iter().to_single_value_query()),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(wrong_grant_type);
}
