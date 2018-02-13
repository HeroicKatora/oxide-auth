use primitives::authorizer::Storage;
use primitives::issuer::TokenMap;
use primitives::generator::RandomGenerator;
use primitives::registrar::{Client, ClientMap};

use code_grant::frontend::{AuthorizationFlow, GrantFlow};

use super::{Allow, CraftedRequest, CraftedResponse, TestGenerator, ToSingleValueQuery};
use super::defaults::*;

struct PkceSetup {
    registrar: ClientMap,
    authorizer: Storage<TestGenerator>,
    issuer: TokenMap<RandomGenerator>,
    auth_token: String,
    verifier: String,
    sha256_challenge: String,
}

impl PkceSetup {
    fn new() -> PkceSetup {
        let client = Client::public(EXAMPLE_CLIENT_ID,
            EXAMPLE_REDIRECT_URI.parse().unwrap(),
            EXAMPLE_SCOPE.parse().unwrap());

        let mut registrar = ClientMap::new();
        registrar.register_client(client);

        let token = "ExampleAuthorizationToken".to_string();
        let authorizer = Storage::new(TestGenerator(token.clone()));
        let issuer = TokenMap::new(RandomGenerator::new(16));

        PkceSetup {
            registrar: registrar,
            authorizer: authorizer,
            issuer: issuer,
            auth_token: token,
            // The following are from https://tools.ietf.org/html/rfc7636#page-18
            sha256_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
            verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
        }
    }

    fn test_correct_access(&mut self, mut auth_request: CraftedRequest, mut access_request: CraftedRequest) {
        use code_grant::extensions::Pkce;

        let pagehandler = Allow(EXAMPLE_OWNER_ID.to_string());
        let pkce_extension = Pkce::required();

        match AuthorizationFlow::new(&self.registrar, &mut self.authorizer)
                .with_extension(&pkce_extension)
                .handle(&mut auth_request, &pagehandler) {
            Ok(ref _response) => (),
            resp => panic!("Expected non-error reponse, got {:?}", resp),
        }

        match GrantFlow::new(&self.registrar, &mut self.authorizer, &mut self.issuer)
                .with_extension(&pkce_extension)
                .handle(&mut access_request) {
            Ok(ref _response) => (),
            resp => panic!("Expected non-error reponse, got {:?}", resp),
        }
    }

    fn test_failed_verification(&mut self, mut auth_request: CraftedRequest, mut access_request: CraftedRequest) {
        use code_grant::extensions::Pkce;

        let pagehandler = Allow(EXAMPLE_OWNER_ID.to_string());
        let pkce_extension = Pkce::required();

        match AuthorizationFlow::new(&self.registrar, &mut self.authorizer)
                .with_extension(&pkce_extension)
                .handle(&mut auth_request, &pagehandler) {
            Ok(ref _response) => (),
            resp => panic!("Expected non-error reponse, got {:?}", resp),
        }

        match GrantFlow::new(&self.registrar, &mut self.authorizer, &mut self.issuer)
                .with_extension(&pkce_extension)
                .handle(&mut access_request) {
            Ok(CraftedResponse::ClientError(_)) => (),
            resp => panic!("Expected non-error reponse, got {:?}", resp),
        }
    }
}

#[test]
fn pkce_correct_verifier() {
    let mut setup = PkceSetup::new();

    let correct_authorization = CraftedRequest {
        query: Some(vec![("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI),
                         ("grant_type", "authorization_code"),
                         ("code_challenge", &setup.sha256_challenge),
                         ("code_challenge_method", "S256")]
            .iter().to_single_value_query()),
        urlbody: None,
        auth: None,
    };

    let correct_access = CraftedRequest {
        query: None,
        urlbody: Some(vec![("grant_type", "authorization_code"),
                           ("code", &setup.auth_token),
                           ("redirect_uri", EXAMPLE_REDIRECT_URI),
                           ("code_verifier", &setup.verifier)]
            .iter().to_single_value_query()),
        auth: None,
    };

    setup.test_correct_access(correct_authorization, correct_access);
}

#[test]
fn pkce_failed_verifier() {
    let mut setup = PkceSetup::new();

    let correct_authorization = CraftedRequest {
        query: Some(vec![("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_uri", EXAMPLE_REDIRECT_URI),
                         ("grant_type", "authorization_code"),
                         ("code_challenge", &setup.sha256_challenge),
                         ("code_challenge_method", "S256")]
            .iter().to_single_value_query()),
        urlbody: None,
        auth: None,
    };

    let correct_access = CraftedRequest {
        query: None,
        urlbody: Some(vec![("grant_type", "authorization_code"),
                           ("code", &setup.auth_token),
                           ("redirect_uri", EXAMPLE_REDIRECT_URI),
                           ("code_verifier", "Notthecorrectverifier")]
            .iter().to_single_value_query()),
        auth: None,
    };

    setup.test_failed_verification(correct_authorization, correct_access);
}
