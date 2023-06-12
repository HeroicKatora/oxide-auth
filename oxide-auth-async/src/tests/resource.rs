use oxide_auth::primitives::issuer::TokenMap;
use oxide_auth::primitives::generator::RandomGenerator;
use oxide_auth::primitives::grant::{Grant, Extensions};
use oxide_auth::{frontends::simple::endpoint::Error, primitives::scope::Scope, endpoint::WebRequest};

use chrono::{Utc, Duration};

use super::CraftedRequest;
use super::defaults::*;
use crate::endpoint::{resource::ResourceFlow, Endpoint};

pub struct ResourceEndpoint<'a> {
    issuer: &'a mut TokenMap<RandomGenerator>,
    scopes: &'a mut [Scope],
}

impl<'a> Endpoint<CraftedRequest> for ResourceEndpoint<'a> {
    type Error = Error<CraftedRequest>;

    fn registrar(&self) -> Option<&(dyn crate::primitives::Registrar + Sync)> {
        None
    }
    fn authorizer_mut(&mut self) -> Option<&mut (dyn crate::primitives::Authorizer + Send)> {
        None
    }
    fn issuer_mut(&mut self) -> Option<&mut (dyn crate::primitives::Issuer + Send)> {
        Some(self.issuer)
    }
    fn response(
        &mut self, _: &mut CraftedRequest, _: oxide_auth::endpoint::Template,
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
        Some(&mut self.scopes)
    }
    fn owner_solicitor(
        &mut self,
    ) -> Option<&mut (dyn crate::endpoint::OwnerSolicitor<CraftedRequest> + Send)> {
        None
    }
}

impl<'a> ResourceEndpoint<'a> {
    pub fn new(issuer: &'a mut TokenMap<RandomGenerator>, scopes: &'a mut [Scope]) -> Self {
        Self { issuer, scopes }
    }
}

struct ResourceSetup {
    issuer: TokenMap<RandomGenerator>,
    authtoken: String,
    wrong_scope_token: String,
    small_scope_token: String,
    resource_scope: [Scope; 1],
}

impl ResourceSetup {
    fn new() -> ResourceSetup {
        use crate::primitives::Issuer;

        // Ensure that valid tokens are 16 bytes long, so we can craft an invalid one
        let mut issuer = TokenMap::new(RandomGenerator::new(16));

        let authtoken = smol::block_on(issuer.issue(Grant {
            client_id: EXAMPLE_CLIENT_ID.to_string(),
            owner_id: EXAMPLE_OWNER_ID.to_string(),
            redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope: "legit needed andmore".parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        }))
        .unwrap();

        let wrong_scope_token = smol::block_on(issuer.issue(Grant {
            client_id: EXAMPLE_CLIENT_ID.to_string(),
            owner_id: EXAMPLE_OWNER_ID.to_string(),
            redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope: "wrong needed".parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        }))
        .unwrap();

        let small_scope_token = smol::block_on(issuer.issue(Grant {
            client_id: EXAMPLE_CLIENT_ID.to_string(),
            owner_id: EXAMPLE_OWNER_ID.to_string(),
            redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope: "legit".parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        }))
        .unwrap();

        ResourceSetup {
            issuer,
            authtoken: authtoken.token,
            wrong_scope_token: wrong_scope_token.token,
            small_scope_token: small_scope_token.token,
            resource_scope: ["needed legit".parse().unwrap()],
        }
    }

    fn test_access_success(&mut self, request: CraftedRequest) {
        let mut resource_flow =
            ResourceFlow::prepare(ResourceEndpoint::new(&mut self.issuer, &mut self.resource_scope))
                .unwrap();
        match smol::block_on(resource_flow.execute(request)) {
            Ok(_) => (),
            Err(ohno) => panic!("Expected an error instead of {:?}", ohno),
        }
    }

    fn test_access_error(&mut self, request: CraftedRequest) {
        let mut resource_flow =
            ResourceFlow::prepare(ResourceEndpoint::new(&mut self.issuer, &mut self.resource_scope))
                .unwrap();
        if let Ok(resp) = smol::block_on(resource_flow.execute(request)) {
            panic!("Expected an error instead of {:?}", resp);
        }
    }
}

#[test]
fn resource_success() {
    let mut setup = ResourceSetup::new();
    let success = CraftedRequest {
        query: None,
        urlbody: None,
        auth: Some("Bearer ".to_string() + &setup.authtoken),
    };

    setup.test_access_success(success);
}

#[test]
fn assert_send() {
    let mut setup = ResourceSetup::new();
    let endpoint = ResourceEndpoint::new(&mut setup.issuer, &mut setup.resource_scope);
    let mut flow = ResourceFlow::prepare(endpoint).unwrap();

    super::assert_send(&flow.execute(CraftedRequest::default()));
}

#[test]
fn resource_no_authorization() {
    // Does not have any authorization
    let no_authorization = CraftedRequest {
        query: None,
        urlbody: None,
        auth: None,
    };

    ResourceSetup::new().test_access_error(no_authorization);
}

#[test]
fn resource_invalid_token() {
    // Does not have any authorization
    let invalid_token = CraftedRequest {
        query: None,
        urlbody: None,
        auth: Some("Bearer ThisisnotavalidtokenTooLong".to_string()),
    };

    ResourceSetup::new().test_access_error(invalid_token);
}

#[test]
fn resource_wrong_method() {
    let mut setup = ResourceSetup::new();
    // Not indicating the `Bearer` authorization method
    let wrong_method = CraftedRequest {
        query: None,
        urlbody: None,
        auth: Some("NotBearer ".to_string() + &setup.authtoken),
    };

    setup.test_access_error(wrong_method);
}

#[test]
fn resource_scope_too_small() {
    let mut setup = ResourceSetup::new();
    // Scope of used token is too small for access
    let scope_too_small = CraftedRequest {
        query: None,
        urlbody: None,
        auth: Some("Bearer ".to_string() + &setup.small_scope_token),
    };

    setup.test_access_error(scope_too_small);
}

#[test]
fn resource_wrong_scope() {
    let mut setup = ResourceSetup::new();
    // Scope of used token does not match the access
    let wrong_scope = CraftedRequest {
        query: None,
        urlbody: None,
        auth: Some("Bearer ".to_string() + &setup.wrong_scope_token),
    };

    setup.test_access_error(wrong_scope);
}
