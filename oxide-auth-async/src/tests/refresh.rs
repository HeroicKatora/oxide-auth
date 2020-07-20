use oxide_auth::primitives::issuer::{IssuedToken, RefreshedToken, TokenMap};
use oxide_auth::primitives::generator::RandomGenerator;
use oxide_auth::primitives::grant::{Grant, Extensions};
use oxide_auth::{
    endpoint::{Scope, WebRequest},
    primitives::registrar::{Client, ClientMap},
    frontends::simple::endpoint::Error,
};

use crate::{
    endpoint::{refresh::RefreshFlow, Endpoint, resource::ResourceFlow},
    primitives::{Issuer},
};

use std::collections::HashMap;

use base64;
use chrono::{Utc, Duration};
use serde_json;

use super::{Body, CraftedRequest, CraftedResponse, Status, ToSingleValueQuery};
use super::{defaults::*, resource::ResourceEndpoint};

struct RefreshTokenEndpoint<'a> {
    registrar: &'a ClientMap,
    issuer: &'a mut TokenMap<RandomGenerator>,
}

impl<'a> RefreshTokenEndpoint<'a> {
    fn new(registrar: &'a ClientMap, issuer: &'a mut TokenMap<RandomGenerator>) -> Self {
        Self { registrar, issuer }
    }
}

impl<'a> Endpoint<CraftedRequest> for RefreshTokenEndpoint<'a> {
    type Error = Error<CraftedRequest>;

    fn registrar(&self) -> Option<&dyn crate::primitives::Registrar> {
        Some(self.registrar)
    }
    fn authorizer_mut(&mut self) -> Option<&mut dyn crate::primitives::Authorizer> {
        None
    }
    fn issuer_mut(&mut self) -> Option<&mut dyn crate::primitives::Issuer> {
        Some(self.issuer)
    }
    fn response(
        &mut self, request: &mut CraftedRequest, kind: oxide_auth::endpoint::Template,
    ) -> Result<<CraftedRequest as WebRequest>::Response, Self::Error> {
        Ok(Default::default())
    }
    fn error(&mut self, _err: oxide_auth::endpoint::OAuthError) -> Self::Error {
        unimplemented!()
    }
    fn web_error(&mut self, _err: <CraftedRequest as WebRequest>::Error) -> Self::Error {
        unimplemented!()
    }
    fn scopes(&mut self) -> Option<&mut dyn oxide_auth::endpoint::Scopes<CraftedRequest>> {
        None
    }
    fn owner_solicitor(&mut self) -> Option<&mut dyn crate::endpoint::OwnerSolicitor<CraftedRequest>> {
        None
    }
}

struct RefreshTokenSetup {
    registrar: ClientMap,
    issuer: TokenMap<RandomGenerator>,
    issued: IssuedToken,
    basic_authorization: String,
}

impl RefreshTokenSetup {
    fn private_client() -> Self {
        let mut registrar = ClientMap::new();
        let mut issuer = TokenMap::new(RandomGenerator::new(16));

        let client = Client::confidential(
            EXAMPLE_CLIENT_ID,
            EXAMPLE_REDIRECT_URI.parse().unwrap(),
            EXAMPLE_SCOPE.parse().unwrap(),
            EXAMPLE_PASSPHRASE.as_bytes(),
        );

        let grant = Grant {
            client_id: EXAMPLE_CLIENT_ID.to_string(),
            owner_id: EXAMPLE_OWNER_ID.to_string(),
            redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope: EXAMPLE_SCOPE.parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        };

        registrar.register_client(client);
        let issued = smol::run(issuer.issue(grant)).unwrap();
        assert!(!issued.refresh.is_empty());

        let basic_authorization =
            base64::encode(&format!("{}:{}", EXAMPLE_CLIENT_ID, EXAMPLE_PASSPHRASE));
        let basic_authorization = format!("Basic {}", basic_authorization);

        RefreshTokenSetup {
            registrar,
            issuer,
            issued,
            basic_authorization,
        }
    }

    fn public_client() -> Self {
        let mut registrar = ClientMap::new();
        let mut issuer = TokenMap::new(RandomGenerator::new(16));

        let client = Client::public(
            EXAMPLE_CLIENT_ID,
            EXAMPLE_REDIRECT_URI.parse().unwrap(),
            EXAMPLE_SCOPE.parse().unwrap(),
        );

        let grant = Grant {
            client_id: EXAMPLE_CLIENT_ID.to_string(),
            owner_id: EXAMPLE_OWNER_ID.to_string(),
            redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope: EXAMPLE_SCOPE.parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        };

        registrar.register_client(client);
        let issued = smol::run(issuer.issue(grant)).unwrap();
        assert!(!issued.refresh.is_empty());

        let basic_authorization = "DO_NOT_USE".into();

        RefreshTokenSetup {
            registrar,
            issuer,
            issued,
            basic_authorization,
        }
    }

    fn assert_success(&mut self, request: CraftedRequest) -> RefreshedToken {
        let mut refresh_flow =
            RefreshFlow::prepare(RefreshTokenEndpoint::new(&self.registrar, &mut self.issuer)).unwrap();
        let response = smol::run(refresh_flow.execute(request)).expect("Expected non-failed reponse");
        assert_eq!(response.status, Status::Ok);
        let body = match response.body {
            Some(Body::Json(body)) => body,
            _ => panic!("Expect json body"),
        };
        let mut body: HashMap<String, String> =
            serde_json::from_str(&body).expect("Expected valid json body");
        let duration: i64 = body.remove("expires_in").unwrap().parse().unwrap();
        RefreshedToken {
            token: body.remove("access_token").expect("Expected a token"),
            refresh: body.remove("refresh_token"),
            until: Utc::now() + Duration::seconds(duration),
        }
    }

    /// Check that the request failed with 400/401.
    fn assert_unauthenticated(&mut self, request: CraftedRequest) {
        let mut refresh_flow =
            RefreshFlow::prepare(RefreshTokenEndpoint::new(&self.registrar, &mut self.issuer)).unwrap();
        let response = smol::run(refresh_flow.execute(request)).expect("Expected non-failed reponse");
        let body = self.assert_json_body(&response);
        if response.status == Status::Unauthorized {
            assert!(response.www_authenticate.is_some());
        }

        assert_eq!(body.get("error").map(String::as_str), Some("invalid_client"));
        self.assert_only_error(body);
    }

    /// The request as malformed and not processed any further.
    fn assert_invalid(&mut self, request: CraftedRequest) {
        let mut refresh_flow =
            RefreshFlow::prepare(RefreshTokenEndpoint::new(&self.registrar, &mut self.issuer)).unwrap();
        let response = smol::run(refresh_flow.execute(request)).expect("Expected non-failed reponse");
        let body = self.assert_json_body(&response);
        assert_eq!(response.status, Status::BadRequest);

        assert_eq!(body.get("error").map(String::as_str), Some("invalid_request"));
        self.assert_only_error(body);
    }

    /// Client authorizes ok but does not match the grant.
    fn assert_invalid_grant(&mut self, request: CraftedRequest) {
        let mut refresh_flow =
            RefreshFlow::prepare(RefreshTokenEndpoint::new(&self.registrar, &mut self.issuer)).unwrap();
        let response = smol::run(refresh_flow.execute(request)).expect("Expected non-failed reponse");
        let body = self.assert_json_body(&response);
        assert_eq!(response.status, Status::BadRequest);

        assert_eq!(body.get("error").map(String::as_str), Some("invalid_grant"));
        self.assert_only_error(body);
    }

    /// Check that the request failed with 401.
    fn assert_wrong_authentication(&mut self, request: CraftedRequest) {
        let mut refresh_flow =
            RefreshFlow::prepare(RefreshTokenEndpoint::new(&self.registrar, &mut self.issuer)).unwrap();
        let response = smol::run(refresh_flow.execute(request)).expect("Expected non-failed reponse");
        assert_eq!(response.status, Status::Unauthorized);
        assert!(response.www_authenticate.is_some());

        let body = self.assert_json_body(&response);

        assert_eq!(body.get("error").map(String::as_str), Some("invalid_client"));
        self.assert_only_error(body);
    }

    fn assert_json_body(&mut self, response: &CraftedResponse) -> HashMap<String, String> {
        let body = match &response.body {
            Some(Body::Json(body)) => body,
            _ => panic!("Expect json body"),
        };
        let body: HashMap<String, String> =
            serde_json::from_str(body).expect("Expected valid json body");
        body
    }

    fn assert_only_error(&mut self, mut body: HashMap<String, String>) {
        let _ = body.remove("error");
        let _ = body.remove("error_description");
        let _ = body.remove("error_uri");
        assert!(body.is_empty());
    }

    fn access_resource(&mut self, token: String) {
        let request = CraftedRequest {
            query: None,
            urlbody: None,
            auth: Some(format!("Bearer {}", token)),
        };
        let mut scopes = [EXAMPLE_SCOPE.parse().unwrap()];
        let mut resource_flow =
            ResourceFlow::prepare(ResourceEndpoint::new(&mut self.issuer, &mut scopes)).unwrap();
        smol::run(resource_flow.execute(request)).expect("Expected access allowed");
    }
}

#[test]
fn access_valid_public() {
    let mut setup = RefreshTokenSetup::public_client();

    let valid_public = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", &setup.issued.refresh),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    let new_token = setup.assert_success(valid_public);
    setup.access_resource(new_token.token);
}

#[test]
fn access_valid_private() {
    let mut setup = RefreshTokenSetup::private_client();

    let valid_private = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", &setup.issued.refresh),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some(setup.basic_authorization.clone()),
    };

    let new_token = setup.assert_success(valid_private);
    setup.access_resource(new_token.token);
}

#[test]
fn public_private_invalid_grant() {
    let mut setup = RefreshTokenSetup::public_client();
    let client = Client::confidential(
        "PrivateClient".into(),
        EXAMPLE_REDIRECT_URI.parse().unwrap(),
        EXAMPLE_SCOPE.parse().unwrap(),
        EXAMPLE_PASSPHRASE.as_bytes(),
    );
    setup.registrar.register_client(client);

    let basic_authorization = base64::encode(&format!("{}:{}", "PrivateClient", EXAMPLE_PASSPHRASE));
    let basic_authorization = format!("Basic {}", basic_authorization);

    let authenticated = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", &setup.issued.refresh),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some(basic_authorization),
    };

    setup.assert_invalid_grant(authenticated);
}

#[test]
fn private_wrong_client_fails() {
    let mut setup = RefreshTokenSetup::private_client();

    let valid_public = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", &setup.issued.refresh),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    setup.assert_unauthenticated(valid_public);

    let wrong_authentication = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", &setup.issued.refresh),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some(format!("Basic {}", base64::encode("Wrong:AndWrong"))),
    };

    setup.assert_wrong_authentication(wrong_authentication);
}

#[test]
fn invalid_request() {
    let mut setup = RefreshTokenSetup::private_client();

    let bad_base64 = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", &setup.issued.refresh),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some(setup.basic_authorization.clone() + "=/"),
    };

    setup.assert_invalid(bad_base64);

    let no_token = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![("grant_type", "refresh_token")]
                .iter()
                .to_single_value_query(),
        ),
        auth: Some(setup.basic_authorization.clone()),
    };

    setup.assert_invalid(no_token);
}

#[test]
fn public_invalid_token() {
    let mut setup = RefreshTokenSetup::public_client();

    let valid_public = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", "not_the_issued_token"),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    setup.assert_invalid_grant(valid_public);
}

#[test]
fn private_invalid_token() {
    let mut setup = RefreshTokenSetup::private_client();

    let valid_private = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", "not_the_issued_token"),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some(setup.basic_authorization.clone()),
    };

    setup.assert_invalid_grant(valid_private);
}
