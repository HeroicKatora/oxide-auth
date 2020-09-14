use std::collections::HashMap;

use oxide_auth::primitives::authorizer::AuthMap;
use oxide_auth::{
    primitives::registrar::{Client, ClientMap, RegisteredUrl},
    frontends::simple::endpoint::Error,
    endpoint::WebRequest,
};

use crate::endpoint::{Endpoint, OwnerSolicitor, authorization::AuthorizationFlow};

use super::{CraftedRequest, Status, TestGenerator, ToSingleValueQuery};
use super::{Allow, Deny};
use super::defaults::*;

struct AuthorizationEndpoint<'a> {
    registrar: &'a ClientMap,
    authorizer: &'a mut AuthMap<TestGenerator>,
    solicitor: &'a mut (dyn OwnerSolicitor<CraftedRequest> + Send + Sync),
}

impl<'a> AuthorizationEndpoint<'a> {
    fn new(
        registrar: &'a ClientMap, authorizer: &'a mut AuthMap<TestGenerator>,
        solicitor: &'a mut (dyn OwnerSolicitor<CraftedRequest> + Send + Sync),
    ) -> Self {
        Self {
            registrar,
            authorizer,
            solicitor,
        }
    }
}

impl<'a> Endpoint<CraftedRequest> for AuthorizationEndpoint<'a> {
    type Error = Error<CraftedRequest>;

    fn registrar(&self) -> Option<&(dyn crate::primitives::Registrar + Sync)> {
        Some(self.registrar)
    }
    fn authorizer_mut(&mut self) -> Option<&mut (dyn crate::primitives::Authorizer + Send)> {
        Some(self.authorizer)
    }
    fn issuer_mut(&mut self) -> Option<&mut (dyn crate::primitives::Issuer + Send)> {
        None
    }
    fn scopes(&mut self) -> Option<&mut dyn oxide_auth::endpoint::Scopes<CraftedRequest>> {
        None
    }
    fn response(
        &mut self, _request: &mut CraftedRequest, _kind: oxide_auth::endpoint::Template,
    ) -> Result<<CraftedRequest as WebRequest>::Response, Self::Error> {
        Ok(Default::default())
    }
    fn error(&mut self, err: oxide_auth::endpoint::OAuthError) -> Self::Error {
        Error::OAuth(err)
    }
    fn web_error(&mut self, err: <CraftedRequest as WebRequest>::Error) -> Self::Error {
        Error::Web(err)
    }
    fn owner_solicitor(&mut self) -> Option<&mut (dyn OwnerSolicitor<CraftedRequest> + Send)> {
        Some(self.solicitor)
    }
}

struct AuthorizationSetup {
    registrar: ClientMap,
    authorizer: AuthMap<TestGenerator>,
}

impl AuthorizationSetup {
    fn new() -> AuthorizationSetup {
        let mut registrar = ClientMap::new();
        let authorizer = AuthMap::new(TestGenerator("AuthToken".to_string()));

        let client = Client::confidential(
            EXAMPLE_CLIENT_ID,
            RegisteredUrl::Exact(EXAMPLE_REDIRECT_URI.parse().unwrap()),
            EXAMPLE_SCOPE.parse().unwrap(),
            EXAMPLE_PASSPHRASE.as_bytes(),
        );
        registrar.register_client(client);
        AuthorizationSetup {
            registrar,
            authorizer,
        }
    }

    fn test_success(&mut self, request: CraftedRequest) {
        let mut solicitor = Allow(EXAMPLE_OWNER_ID.to_string());
        let mut authorization_flow = AuthorizationFlow::prepare(AuthorizationEndpoint::new(
            &mut self.registrar,
            &mut self.authorizer,
            &mut solicitor,
        ))
        .unwrap();
        let response = smol::run(authorization_flow.execute(request)).expect("Should not error");

        assert_eq!(response.status, Status::Redirect);

        match response.location {
            Some(ref url) if url.as_str().find("error").is_none() => (),
            other => panic!("Expected successful redirect: {:?}", other),
        }
    }

    fn test_silent_error(&mut self, request: CraftedRequest) {
        let mut solicitor = Allow(EXAMPLE_OWNER_ID.to_string());
        let mut authorization_flow = AuthorizationFlow::prepare(AuthorizationEndpoint::new(
            &mut self.registrar,
            &mut self.authorizer,
            &mut solicitor,
        ))
        .unwrap();
        match smol::run(authorization_flow.execute(request)) {
            Ok(ref resp) if resp.location.is_some() => panic!("Redirect without client id {:?}", resp),
            Ok(resp) => panic!("Response without client id {:?}", resp),
            Err(_) => (),
        }
    }

    fn test_error_redirect<P: Send + Sync>(&mut self, request: CraftedRequest, mut pagehandler: P)
    where
        P: OwnerSolicitor<CraftedRequest>,
    {
        let mut authorization_flow = AuthorizationFlow::prepare(AuthorizationEndpoint::new(
            &mut self.registrar,
            &mut self.authorizer,
            &mut pagehandler,
        ))
        .unwrap();
        let response = smol::run(authorization_flow.execute(request));

        let response = match response {
            Err(resp) => panic!("Expected redirect with error set: {:?}", resp),
            Ok(resp) => resp,
        };

        match response.location {
            Some(ref url)
                if url
                    .query_pairs()
                    .collect::<HashMap<_, _>>()
                    .get("error")
                    .is_some() =>
            {
                ()
            }
            other => panic!("Expected location with error set description: {:?}", other),
        }
    }
}

#[test]
fn auth_success() {
    let success = CraftedRequest {
        query: Some(
            vec![
                ("response_type", "code"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
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
        query: Some(
            vec![
                ("response_type", "code"),
                ("client_id", "SomeOtherClient"),
                ("redirect_uri", "https://wrong.client.example/endpoint"),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_silent_error(unknown_client);
}

#[test]
fn auth_request_silent_mismatching_redirect() {
    // The redirect_uri does not match
    let mismatching_redirect = CraftedRequest {
        query: Some(
            vec![
                ("response_type", "code"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("redirect_uri", "https://wrong.client.example/endpoint"),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_silent_error(mismatching_redirect);
}

#[test]
fn auth_request_silent_invalid_redirect() {
    // The redirect_uri is not an uri ('\' is not allowed to appear in the scheme)
    let invalid_redirect = CraftedRequest {
        query: Some(
            vec![
                ("response_type", "code"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("redirect_uri", "\\://"),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_silent_error(invalid_redirect);
}

#[test]
fn auth_request_error_denied() {
    // Used in conjunction with a denying authorization handler below
    let denied_request = CraftedRequest {
        query: Some(
            vec![
                ("response_type", "code"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_error_redirect(denied_request, Deny);
}

#[test]
fn auth_request_error_unsupported_method() {
    // Requesting an authorization token for a method other than code
    let unsupported_method = CraftedRequest {
        query: Some(
            vec![
                ("response_type", "other_method"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new()
        .test_error_redirect(unsupported_method, Allow(EXAMPLE_OWNER_ID.to_string()));
}

#[test]
fn auth_request_error_malformed_scope() {
    // A scope with malformed formatting
    let malformed_scope = CraftedRequest {
        query: Some(
            vec![
                ("response_type", "code"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
                ("scope", "\"no quotes (0x22) allowed\""),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_error_redirect(malformed_scope, Allow(EXAMPLE_OWNER_ID.to_string()));
}
