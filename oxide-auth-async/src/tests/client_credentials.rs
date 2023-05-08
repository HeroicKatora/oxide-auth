use oxide_auth::primitives::authorizer::AuthMap;
use oxide_auth::primitives::registrar::{Client, ClientMap, RegisteredUrl};
use oxide_auth::primitives::issuer::TokenMap;
use oxide_auth::{frontends::simple::endpoint::Error, endpoint::WebRequest};

use crate::{
    endpoint::{client_credentials::ClientCredentialsFlow, Endpoint, OwnerSolicitor},
};

use super::{CraftedRequest, Status, TestGenerator, ToSingleValueQuery};
use super::{Allow, Deny};
use super::defaults::*;

struct ClientCredentialsEndpoint<'a> {
    registrar: &'a ClientMap,
    authorizer: &'a mut AuthMap<TestGenerator>,
    issuer: &'a mut TokenMap<TestGenerator>,
    solicitor: &'a mut (dyn OwnerSolicitor<CraftedRequest> + Send + Sync),
}

impl<'a> ClientCredentialsEndpoint<'a> {
    fn new(
        registrar: &'a ClientMap, authorizer: &'a mut AuthMap<TestGenerator>,
        issuer: &'a mut TokenMap<TestGenerator>,
        solicitor: &'a mut (dyn OwnerSolicitor<CraftedRequest> + Send + Sync),
    ) -> Self {
        Self {
            registrar,
            authorizer,
            issuer,
            solicitor,
        }
    }
}

impl<'a> Endpoint<CraftedRequest> for ClientCredentialsEndpoint<'a> {
    type Error = Error<CraftedRequest>;

    fn registrar(&self) -> Option<&(dyn crate::primitives::Registrar + Sync)> {
        Some(self.registrar)
    }
    fn authorizer_mut(&mut self) -> Option<&mut (dyn crate::primitives::Authorizer + Send)> {
        Some(self.authorizer)
    }
    fn issuer_mut(&mut self) -> Option<&mut (dyn crate::primitives::Issuer + Send)> {
        Some(self.issuer)
    }
    fn scopes(&mut self) -> Option<&mut dyn oxide_auth::endpoint::Scopes<CraftedRequest>> {
        None
    }
    fn response(
        &mut self, _: &mut CraftedRequest, _: oxide_auth::endpoint::Template,
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

struct ClientCredentialsSetup {
    registrar: ClientMap,
    authorizer: AuthMap<TestGenerator>,
    issuer: TokenMap<TestGenerator>,
    basic_authorization: String,
    allow_credentials_in_body: bool,
}

impl ClientCredentialsSetup {
    fn new() -> ClientCredentialsSetup {
        let mut registrar = ClientMap::new();
        let authorizer = AuthMap::new(TestGenerator("AuthToken".to_string()));
        let issuer = TokenMap::new(TestGenerator("AuthToken".to_owned()));

        let client = Client::confidential(
            EXAMPLE_CLIENT_ID,
            RegisteredUrl::Semantic(EXAMPLE_REDIRECT_URI.parse().unwrap()),
            EXAMPLE_SCOPE.parse().unwrap(),
            EXAMPLE_PASSPHRASE.as_bytes(),
        );
        registrar.register_client(client);
        let basic_authorization =
            base64::encode(format!("{}:{}", EXAMPLE_CLIENT_ID, EXAMPLE_PASSPHRASE));
        ClientCredentialsSetup {
            registrar,
            authorizer,
            issuer,
            basic_authorization,
            allow_credentials_in_body: false,
        }
    }

    fn public_client() -> Self {
        let mut registrar = ClientMap::new();
        let authorizer = AuthMap::new(TestGenerator("AuthToken".to_string()));
        let issuer = TokenMap::new(TestGenerator("AccessToken".to_owned()));

        let client = Client::public(
            EXAMPLE_CLIENT_ID,
            RegisteredUrl::Semantic(EXAMPLE_REDIRECT_URI.parse().unwrap()),
            EXAMPLE_SCOPE.parse().unwrap(),
        );
        registrar.register_client(client);
        let basic_authorization =
            base64::encode(format!("{}:{}", EXAMPLE_CLIENT_ID, EXAMPLE_PASSPHRASE));
        ClientCredentialsSetup {
            registrar,
            authorizer,
            issuer,
            basic_authorization,
            allow_credentials_in_body: false,
        }
    }

    fn test_success<S>(&mut self, request: CraftedRequest, mut solicitor: S)
    where
        S: OwnerSolicitor<CraftedRequest> + Send + Sync,
    {
        let mut flow = ClientCredentialsFlow::prepare(ClientCredentialsEndpoint::new(
            &self.registrar,
            &mut self.authorizer,
            &mut self.issuer,
            &mut solicitor,
        ))
        .unwrap();

        flow.allow_credentials_in_body(self.allow_credentials_in_body);
        let response = smol::block_on(flow.execute(request)).expect("Expected non-error response");

        assert_eq!(response.status, Status::Ok);
    }

    fn test_bad_request<S>(&mut self, request: CraftedRequest, mut solicitor: S)
    where
        S: OwnerSolicitor<CraftedRequest> + Send + Sync,
    {
        let mut flow = ClientCredentialsFlow::prepare(ClientCredentialsEndpoint::new(
            &self.registrar,
            &mut self.authorizer,
            &mut self.issuer,
            &mut solicitor,
        ))
        .unwrap();

        flow.allow_credentials_in_body(self.allow_credentials_in_body);
        let response = smol::block_on(flow.execute(request)).expect("Expected non-error response");

        assert_eq!(response.status, Status::BadRequest);
    }

    fn test_unauthorized<S>(&mut self, request: CraftedRequest, mut solicitor: S)
    where
        S: OwnerSolicitor<CraftedRequest> + Send + Sync,
    {
        let mut flow = ClientCredentialsFlow::prepare(ClientCredentialsEndpoint::new(
            &self.registrar,
            &mut self.authorizer,
            &mut self.issuer,
            &mut solicitor,
        ))
        .unwrap();

        flow.allow_credentials_in_body(self.allow_credentials_in_body);
        let response = smol::block_on(flow.execute(request)).expect("Expected non-error response");

        assert_eq!(response.status, Status::Unauthorized);
    }
}

#[test]
fn client_credentials_success() {
    let mut setup = ClientCredentialsSetup::new();
    let success = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![("grant_type", "client_credentials")]
                .iter()
                .to_single_value_query(),
        ),
        auth: Some(format!("Basic {}", setup.basic_authorization)),
    };

    setup.test_success(success, Allow(EXAMPLE_CLIENT_ID.to_owned()));
}

#[test]
fn client_credentials_success_changed_owner() {
    let mut setup = ClientCredentialsSetup::new();
    let success = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![("grant_type", "client_credentials")]
                .iter()
                .to_single_value_query(),
        ),
        auth: Some(format!("Basic {}", setup.basic_authorization)),
    };

    setup.test_success(success, Allow("OtherOwnerId".to_owned()));
}

#[test]
fn client_credentials_deny_public_client() {
    let mut setup = ClientCredentialsSetup::public_client();
    let public_client = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![
                ("grant_type", "client_credentials"),
                ("client_id", EXAMPLE_CLIENT_ID),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    setup.test_bad_request(public_client, Deny);

    #[test]
    fn client_credentials_deny_incorrect_credentials() {
        let mut setup = ClientCredentialsSetup::new();
        let basic_authorization = base64::encode(format!("{}:the wrong passphrase", EXAMPLE_CLIENT_ID));
        let wrong_credentials = CraftedRequest {
            query: None,
            urlbody: Some(
                vec![("grant_type", "client_credentials")]
                    .iter()
                    .to_single_value_query(),
            ),
            auth: Some(format!("Basic {}", basic_authorization)),
        };

        setup.test_unauthorized(wrong_credentials, Allow(EXAMPLE_CLIENT_ID.to_owned()));
    }
}

#[test]
fn client_credentials_deny_missing_credentials() {
    let mut setup = ClientCredentialsSetup::new();
    let missing_credentials = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![
                ("grant_type", "client_credentials"),
                ("client_id", EXAMPLE_CLIENT_ID),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    setup.test_bad_request(missing_credentials, Allow(EXAMPLE_CLIENT_ID.to_owned()));
}

#[test]
fn client_credentials_deny_unknown_client_missing_password() {
    // The client_id is not registered
    let unknown_client = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![
                ("grant_type", "client_credentials"),
                ("client_id", "SomeOtherClient"),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    ClientCredentialsSetup::new().test_bad_request(unknown_client, Allow("SomeOtherClient".to_owned()));
}

#[test]
fn client_credentials_deny_body_missing_password() {
    let mut setup = ClientCredentialsSetup::new();
    setup.allow_credentials_in_body = true;
    // The client_id is not registered
    let unknown_client = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![
                ("grant_type", "client_credentials"),
                ("client_id", EXAMPLE_CLIENT_ID),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    setup.test_bad_request(unknown_client, Allow(EXAMPLE_CLIENT_ID.to_owned()));
}

#[test]
fn client_credentials_deny_unknown_client() {
    // The client_id is not registered
    let mut setup = ClientCredentialsSetup::new();
    let basic_authorization = base64::encode(format!("{}:{}", "SomeOtherClient", EXAMPLE_PASSPHRASE));
    let unknown_client = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![("grant_type", "client_credentials")]
                .iter()
                .to_single_value_query(),
        ),
        auth: Some(format!("Basic {}", basic_authorization)),
    };

    // Do not leak the information that this is unknown. It must appear as a bad login attempt.
    setup.test_unauthorized(unknown_client, Allow("SomeOtherClient".to_owned()));
}

#[test]
fn client_body_credentials() {
    let mut setup = ClientCredentialsSetup::new();
    setup.allow_credentials_in_body = true;

    // The client_id is not registered
    let unknown_client = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![
                ("grant_type", "client_credentials"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("client_secret", EXAMPLE_PASSPHRASE),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    setup.test_success(unknown_client, Allow(EXAMPLE_OWNER_ID.to_owned()));
}

#[test]
fn client_duplicate_credentials_denied() {
    let mut setup = ClientCredentialsSetup::new();
    setup.allow_credentials_in_body = true;

    // Both body and authorization header is not allowed.
    let unknown_client = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![
                ("grant_type", "client_credentials"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("client_secret", EXAMPLE_PASSPHRASE),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some(setup.basic_authorization.clone()),
    };

    setup.test_bad_request(unknown_client, Allow(EXAMPLE_OWNER_ID.to_owned()));
}

#[test]
fn client_credentials_request_error_malformed_scope() {
    let mut setup = ClientCredentialsSetup::new();
    // A scope with malformed formatting
    let malformed_scope = CraftedRequest {
        query: None,
        urlbody: Some(
            vec![
                ("grant_type", "client_credentials"),
                ("scope", "\"no quotes (0x22) allowed\""),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some(format!("Basic {}", setup.basic_authorization)),
    };

    setup.test_bad_request(malformed_scope, Allow(EXAMPLE_OWNER_ID.to_owned()));
}
