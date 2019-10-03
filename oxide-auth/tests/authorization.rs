extern crate oxide_auth;
extern crate oxide_auth_ring;
extern crate base64;
extern crate chrono;
extern crate serde_json;
extern crate url;

use std::collections::HashMap;

use oxide_auth::primitives::authorizer::AuthMap;
use oxide_auth::primitives::registrar::{Client, ClientMap};
use oxide_auth::endpoint::{OwnerSolicitor};
use oxide_auth::frontends::simple::endpoint::authorization_flow;
use oxide_auth_ring::registrar::Pbkdf2;

#[path = "./mod.rs"]
#[allow(dead_code)]
mod helpers;

use helpers::{CraftedRequest, Status, TestGenerator, ToSingleValueQuery};
use helpers::{Allow, Deny};
use helpers::defaults::*;


struct AuthorizationSetup {
    registrar: ClientMap,
    authorizer: AuthMap<TestGenerator>,
}

impl AuthorizationSetup {
    fn new() -> AuthorizationSetup {
        let mut registrar = ClientMap::new(Pbkdf2::default());
        let authorizer = AuthMap::new(TestGenerator("AuthToken".to_string()));

        let client = Client::confidential(EXAMPLE_CLIENT_ID,
            EXAMPLE_REDIRECT_URI.parse().unwrap(),
            EXAMPLE_SCOPE.parse().unwrap(),
            EXAMPLE_PASSPHRASE.as_bytes());
        registrar.register_client(client);
        AuthorizationSetup {
            registrar,
            authorizer,
        }
    }

    fn test_success(&mut self, request: CraftedRequest) {
        let response = authorization_flow(&mut self.registrar, &mut self.authorizer, &mut Allow(EXAMPLE_OWNER_ID.to_string()))
            .execute(request)
            .expect("Should not error");
        
        assert_eq!(response.status, Status::Redirect);

        match response.location {
            Some(ref url) if url.as_str().find("error").is_none() => (),
            other => panic!("Expected successful redirect: {:?}", other),
        }
    }

    fn test_silent_error(&mut self, request: CraftedRequest) {
        match authorization_flow(&mut self.registrar, &mut self.authorizer, &mut Allow(EXAMPLE_OWNER_ID.to_string()))
            .execute(request)
        {
            Ok(ref resp) if resp.location.is_some() => panic!("Redirect without client id {:?}", resp),
            Ok(resp) => panic!("Response without client id {:?}", resp),
            Err(_) => (),
        }
    }

    fn test_error_redirect<P>(&mut self, request: CraftedRequest, mut pagehandler: P)
        where P: OwnerSolicitor<CraftedRequest> 
    {
        let response = authorization_flow(&mut self.registrar, &mut self.authorizer, &mut pagehandler).execute(request);

        let response = match response {
            Err(resp) => panic!("Expected redirect with error set: {:?}", resp),
            Ok(resp) => resp,
        };

        match response.location {
            Some(ref url) if url.query_pairs().collect::<HashMap<_, _>>().get("error").is_some() => (),
            other => panic!("Expected location with error set description: {:?}", other),
        }
    }
}

#[test]
fn auth_success() {
    let success = CraftedRequest {
        query: Some(vec![("response_type", "code"),
                         ("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI)]
            .iter().to_single_value_query()),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_success(success);
}

#[test]
fn auth_request_silent_missing_client() {
    let missing_client = CraftedRequest {
        query: Some(vec![("response_type", "code")].iter().to_single_value_query()),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_silent_error(missing_client);
}

#[test]
fn auth_request_silent_unknown_client() {
    // The client_id is not registered
    let unknown_client = CraftedRequest {
        query: Some(vec![("response_type", "code"),
                         ("client_id", "SomeOtherClient"),
                         ("redirect_uri", "https://wrong.client.example/endpoint")]
            .iter().to_single_value_query()),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_silent_error(unknown_client);
}

#[test]
fn auth_request_silent_mismatching_redirect() {
    // The redirect_uri does not match
    let mismatching_redirect = CraftedRequest {
        query: Some(vec![("response_type", "code"),
                         ("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_uri", "https://wrong.client.example/endpoint")]
            .iter().to_single_value_query()),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_silent_error(mismatching_redirect);
}

#[test]
fn auth_request_silent_invalid_redirect() {
    // The redirect_uri is not an uri ('\' is not allowed to appear in the scheme)
    let invalid_redirect = CraftedRequest {
        query: Some(vec![("response_type", "code"),
                         ("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_uri", "\\://")]
            .iter().to_single_value_query()),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_silent_error(invalid_redirect);
}

#[test]
fn auth_request_error_denied() {
    // Used in conjunction with a denying authorization handler below
    let denied_request = CraftedRequest {
        query: Some(vec![("response_type", "code"),
                         ("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI)]
            .iter().to_single_value_query()),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_error_redirect(denied_request, Deny);
}

#[test]
fn auth_request_error_unsupported_method() {
    // Requesting an authorization token for a method other than code
    let unsupported_method = CraftedRequest {
        query: Some(vec![("response_type", "other_method"),
                         ("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI)]
            .iter().to_single_value_query()),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_error_redirect(unsupported_method,
        Allow(EXAMPLE_OWNER_ID.to_string()));
}

#[test]
fn auth_request_error_malformed_scope() {
    // A scope with malformed formatting
    let malformed_scope = CraftedRequest {
        query: Some(vec![("response_type", "code"),
                         ("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI),
                         ("scope", "\"no quotes (0x22) allowed\"")]
            .iter().to_single_value_query()),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_error_redirect(malformed_scope,
        Allow(EXAMPLE_OWNER_ID.to_string()));
}
