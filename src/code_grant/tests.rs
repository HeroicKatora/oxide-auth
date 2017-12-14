use super::frontend::*;
use super::backend::{CodeRef, ErrorUrl, IssuerRef, GuardRef};
use primitives::authorizer::Storage;
use primitives::generator::{TokenGenerator, RandomGenerator};
use primitives::issuer::TokenMap;
use primitives::registrar::{Client, ClientMap, PreGrant};
use primitives::scope::Scope;
use primitives::grant::{GrantRef, GrantRequest};

use std::borrow::Cow;
use std::collections::HashMap;

use url::Url;
use serde_json;
use base64;

struct CraftedRequest {
    query: Option<HashMap<String, Vec<String>>>,
    urlbody: Option<HashMap<String, Vec<String>>>,
    auth: Option<String>,
}

#[derive(Debug)]
enum CraftedResponse {
    Redirect(Url),
    Text(String),
    Json(String),
    RedirectFromError(Url),
    ClientError(Box<CraftedResponse>),
    Unauthorized(Box<CraftedResponse>),
    Authorization(Box<CraftedResponse>, String),
}

impl WebRequest for CraftedRequest {
    type Response = CraftedResponse;
    type Error = OAuthError;

    fn query(&mut self) -> Result<HashMap<String, Vec<String>>, ()> {
        self.query.clone().ok_or(())
    }

    fn urlbody(&mut self) -> Result<&HashMap<String, Vec<String>>, ()> {
        self.urlbody.as_ref().ok_or(())
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, ()> {
        Ok(self.auth.as_ref().map(|bearer| bearer.as_str().into()))
    }
}

impl WebResponse for CraftedResponse {
    type Error = OAuthError;
    fn redirect(url: Url) -> Result<Self, OAuthError> {
        Ok(CraftedResponse::Redirect(url))
    }

    fn text(text: &str) -> Result<Self, OAuthError> {
        Ok(CraftedResponse::Text(text.to_string()))
    }

    fn json(data: &str) -> Result<Self, OAuthError> {
        Ok(CraftedResponse::Json(data.to_string()))
    }

    fn redirect_error(target: ErrorUrl) -> Result<Self, OAuthError> {
        Ok(CraftedResponse::RedirectFromError(target.into()))
    }

    fn as_client_error(self) -> Result<Self, OAuthError> {
        Ok(CraftedResponse::ClientError(self.into()))
    }

    fn as_unauthorized(self) -> Result<Self, OAuthError> {
        Ok(CraftedResponse::Unauthorized(self.into()))
    }

    fn with_authorization(self, kind: &str) -> Result<Self, OAuthError> {
        Ok(CraftedResponse::Authorization(self.into(), kind.to_string()))
    }
}

struct TestGenerator(String);

impl TokenGenerator for TestGenerator {
    fn generate(&self, _grant: &GrantRef) -> String {
        self.0.clone()
    }
}

struct Allow(String);
struct Deny;

impl OwnerAuthorizer for Allow {
    type Request = CraftedRequest;
    fn get_owner_authorization(&self, _: &mut CraftedRequest, _: &PreGrant)
    -> Result<(Authentication, CraftedResponse), OAuthError> {
        Ok((Authentication::Authenticated(self.0.clone()), CraftedResponse::Text("".to_string())))
    }
}

impl OwnerAuthorizer for Deny {
    type Request = CraftedRequest;
    fn get_owner_authorization(&self, _: &mut CraftedRequest, _: &PreGrant)
    -> Result<(Authentication, CraftedResponse), OAuthError> {
        Ok((Authentication::Failed, CraftedResponse::Text("".to_string())))
    }
}

trait ToSingleValueQuery {
    fn as_single_value_query(self) -> HashMap<String, Vec<String>>;
}

impl<'r, I, K, V> ToSingleValueQuery for I where
    I: Iterator<Item=&'r (K, V)>,
    K: AsRef<str> + 'r,
    V: AsRef<str> + 'r {
    fn as_single_value_query(self) -> HashMap<String, Vec<String>> {
        self.map(|&(ref k, ref v)| (k.as_ref().to_string(), vec![v.as_ref().to_string()])).collect()
    }
}

struct AuthorizationSetup {
    registrar: ClientMap,
    authorizer: Storage<TestGenerator>,
}

const EXAMPLE_CLIENT_ID: &str = "ClientId";
const EXAMPLE_OWNER_ID: &str = "Owner";
const EXAMPLE_PASSPHRASE: &str = "VGhpcyBpcyBhIHZlcnkgc2VjdXJlIHBhc3NwaHJhc2UK";
const EXAMPLE_REDIRECT_URL: &str = "https://client.example/endpoint";
const EXAMPLE_SCOPE: &str = "example default";

impl AuthorizationSetup {
    fn new() -> AuthorizationSetup {
        let mut registrar = ClientMap::new();
        let authorizer = Storage::new(TestGenerator("AuthToken".to_string()));

        let client = Client::confidential(EXAMPLE_CLIENT_ID,
            EXAMPLE_REDIRECT_URL.parse().unwrap(),
            EXAMPLE_SCOPE.parse().unwrap(),
            EXAMPLE_PASSPHRASE.as_bytes());
        registrar.register_client(client);
        AuthorizationSetup {
            registrar,
            authorizer,
        }
    }

    fn test_silent_error(&mut self, mut request: CraftedRequest) {
        let prepared = AuthorizationFlow::prepare(&mut request).expect("Failure during authorization preparation");
        let pagehandler = Allow(EXAMPLE_OWNER_ID.to_string());
        match AuthorizationFlow::handle(CodeRef::with(&mut self.registrar, &mut self.authorizer), prepared, &pagehandler) {
            Ok(CraftedResponse::Redirect(url))
                => panic!("Redirection without client id {:?}", url),
            Ok(resp) => panic!("Response without client id {:?}", resp),
            Err(_) => (),
        };
    }

    fn test_error_redirect (&mut self, mut request: CraftedRequest, pagehandler: &OwnerAuthorizer<Request=CraftedRequest>) {
        let prepared = AuthorizationFlow::prepare(&mut request).expect("Failure during authorization preparation");
        match AuthorizationFlow::handle(CodeRef::with(&mut self.registrar, &mut self.authorizer), prepared, pagehandler) {
            Ok(CraftedResponse::RedirectFromError(ref url))
            if url.query_pairs().collect::<HashMap<_, _>>().get("error").is_some()
                => (),
            resp
                => panic!("Expected redirect with error set: {:?}", resp),
        };
    }
}

#[test]
fn authorize_public() {
    let mut registrar = ClientMap::new();
    let mut authorizer = Storage::new(TestGenerator("AuthToken".to_string()));
    let mut issuer = TokenMap::new(TestGenerator("AcessToken".to_string()));

    let client_id = "ClientId";
    let owner_id = "Owner";
    let redirect_url = "https://client.example/endpoint";

    let client = Client::public(client_id, Url::parse(redirect_url).unwrap(), "default".parse().unwrap());
    registrar.register_client(client);

    let mut authrequest = CraftedRequest {
        query: Some(vec![("client_id", client_id),
                         ("redirect_url", redirect_url),
                         ("response_type", "code")]
            .iter().as_single_value_query()),
        urlbody: Some(HashMap::new()),
        auth: None,
    };

    let prepared = AuthorizationFlow::prepare(&mut authrequest).expect("Failure during authorization preparation");
    let pagehandler = Allow(owner_id.to_string());
    match AuthorizationFlow::handle(CodeRef::with(&mut registrar, &mut authorizer), prepared, &pagehandler)
          .expect("Failure during authorization handling") {
        CraftedResponse::Redirect(ref url) if url.as_str() == "https://client.example/endpoint?code=AuthToken"
            => (),
        resp => panic!("{:?}", resp),
    };

    let mut tokenrequest = CraftedRequest {
        query: Some(HashMap::new()),
        urlbody: Some(vec![("client_id", client_id),
                           ("redirect_url", redirect_url),
                           ("code", "AuthToken"),
                           ("grant_type", "authorization_code")]
            .iter().as_single_value_query()),
        auth: None,
    };

    let prepared = GrantFlow::prepare(&mut tokenrequest).expect("Failure during access token preparation");
    let (token, scope) = match GrantFlow::handle(IssuerRef::with(&mut registrar, &mut authorizer, &mut issuer), prepared)
          .expect("Failure during access token handling") {
        CraftedResponse::Json(json)
            => {
                let parsed: HashMap<String, String> = serde_json::from_str(&json).unwrap();
                assert!(parsed.get("error").is_none());
                assert!(parsed.get("expires_in").unwrap().parse::<i32>().unwrap() > 0);
                let token = parsed.get("access_token").unwrap().to_string();
                let scope = parsed.get("scope").unwrap().to_string();
                (token, scope)
            },
        resp => panic!("{:?}", resp),
    };

    let mut accessrequest = CraftedRequest {
        query: None,
        urlbody: None,
        auth: Some("Bearer ".to_string() + &token),
    };

    let prepared = AccessFlow::prepare(&mut accessrequest).expect("Failure during access preparation");
    let scope: [Scope; 1] = [scope.parse().unwrap()];
    AccessFlow::handle(GuardRef::with(&mut issuer, &scope), prepared).expect("Failed to authorize");
}

#[test]
fn authorize_confidential() {
    let mut registrar = ClientMap::new();
    let mut authorizer = Storage::new(TestGenerator("AuthToken".to_string()));
    let mut issuer = TokenMap::new(TestGenerator("AcessToken".to_string()));

    let client_id = "ClientId";
    let owner_id = "Owner";
    let redirect_url = "https://client.example/endpoint";
    let passphrase = "VGhpcyBpcyBhIHZlcnkgc2VjdXJlIHBhc3NwaHJhc2UK";

    let client = Client::confidential(client_id, Url::parse(redirect_url).unwrap(), "default".parse().unwrap(),
        passphrase.as_bytes());
    registrar.register_client(client);

    let mut authrequest = CraftedRequest {
        query: Some(vec![("client_id", client_id),
                         ("redirect_url", redirect_url),
                         ("response_type", "code")]
            .iter().as_single_value_query()),
        urlbody: Some(HashMap::new()),
        auth: None,
    };

    let prepared = AuthorizationFlow::prepare(&mut authrequest).expect("Failure during authorization preparation");
    let pagehandler = Allow(owner_id.to_string());
    match AuthorizationFlow::handle(CodeRef::with(&mut registrar, &mut authorizer), prepared, &pagehandler)
          .expect("Failure during authorization handling") {
        CraftedResponse::Redirect(ref url) if url.as_str() == "https://client.example/endpoint?code=AuthToken"
            => (),
        resp => panic!("{:?}", resp)
    };

    let mut tokenrequest = CraftedRequest {
        query: Some(HashMap::new()),
        urlbody: Some(vec![("redirect_url", redirect_url),
                           ("code", "AuthToken"),
                           ("grant_type", "authorization_code")]
            .iter().as_single_value_query()),
        auth: Some("Basic ".to_string() + &base64::encode(&(client_id.to_string() + ":" + passphrase))),
    };

    let prepared = GrantFlow::prepare(&mut tokenrequest).expect("Failure during access token preparation");
    let (token, scope) = match GrantFlow::handle(IssuerRef::with(&mut registrar, &mut authorizer, &mut issuer), prepared)
          .expect("Failure during access token handling") {
        CraftedResponse::Json(json)
            => {
                let parsed: HashMap<String, String> = serde_json::from_str(&json).unwrap();
                assert!(parsed.get("error").is_none());
                assert!(parsed.get("expires_in").unwrap().parse::<i32>().unwrap() > 0);
                let token = parsed.get("access_token").unwrap().to_string();
                let scope = parsed.get("scope").unwrap().to_string();
                (token, scope)
            },
        resp => panic!("{:?}", resp),
    };

    let mut accessrequest = CraftedRequest {
        query: None,
        urlbody: None,
        auth: Some("Bearer ".to_string() + &token),
    };

    let prepared = AccessFlow::prepare(&mut accessrequest).expect("Failure during access preparation");
    let scope: [Scope; 1] = [scope.parse().unwrap()];
    AccessFlow::handle(GuardRef::with(&mut issuer, &scope), prepared).expect("Failed to authorize");
}

#[test]
fn auth_request_silent_missing_client() {
    let missing_client = CraftedRequest {
        query: Some(vec![("response_type", "code")].iter().as_single_value_query()),
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
                         ("redirect_url", "https://wrong.client.example/endpoint")]
            .iter().as_single_value_query()),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_silent_error(unknown_client);
}

#[test]
fn auth_request_silent_mismatching_redirect() {
    // The redirect_url does not match
    let mismatching_redirect = CraftedRequest {
        query: Some(vec![("response_type", "code"),
                         ("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_url", "https://wrong.client.example/endpoint")]
            .iter().as_single_value_query()),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_silent_error(mismatching_redirect);
}

#[test]
fn auth_request_silent_invalid_redirect() {
    // The redirect_url is not an url
    let invalid_redirect = CraftedRequest {
        query: Some(vec![("response_type", "code"),
                         ("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_url", "notanurl\x0Abogus\\")]
            .iter().as_single_value_query()),
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
                         ("redirect_url", EXAMPLE_REDIRECT_URL)]
            .iter().as_single_value_query()),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_error_redirect(denied_request, &Deny);
}

#[test]
fn auth_request_error_unsupported_method() {
    // Requesting an authorization token for a method other than code
    let unsupported_method = CraftedRequest {
        query: Some(vec![("response_type", "other_method"),
                         ("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_url", EXAMPLE_REDIRECT_URL)]
            .iter().as_single_value_query()),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_error_redirect(unsupported_method,
        &Allow(EXAMPLE_OWNER_ID.to_string()));
}

#[test]
fn auth_request_error_malformed_scope() {
    // A scope with malformed formatting
    let malformed_scope = CraftedRequest {
        query: Some(vec![("response_type", "code"),
                         ("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_url", EXAMPLE_REDIRECT_URL),
                         ("scope", "\"no quotes (0x22) allowed\"")]
            .iter().as_single_value_query()),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_error_redirect(malformed_scope,
        &Allow(EXAMPLE_OWNER_ID.to_string()));
}

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
            EXAMPLE_REDIRECT_URL.parse().unwrap(),
            EXAMPLE_SCOPE.parse().unwrap(),
            EXAMPLE_PASSPHRASE.as_bytes());

        let authrequest = GrantRequest {
            client_id: EXAMPLE_CLIENT_ID,
            owner_id: EXAMPLE_OWNER_ID,
            redirect_url: &EXAMPLE_REDIRECT_URL.parse().unwrap(),
            scope: &EXAMPLE_SCOPE.parse().unwrap(),
        };

        let authtoken = authorizer.authorize(authrequest);
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
            EXAMPLE_REDIRECT_URL.parse().unwrap(),
            EXAMPLE_SCOPE.parse().unwrap());

        let authrequest = GrantRequest {
            client_id: EXAMPLE_CLIENT_ID,
            owner_id: EXAMPLE_OWNER_ID,
            redirect_url: &EXAMPLE_REDIRECT_URL.parse().unwrap(),
            scope: &EXAMPLE_SCOPE.parse().unwrap(),
        };

        let authtoken = authorizer.authorize(authrequest);
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

    fn test_simple_error(&mut self, mut req: CraftedRequest) {
        let prepared = GrantFlow::prepare(&mut req).expect("Failed during access request preparation");
        match GrantFlow::handle(IssuerRef::with(&self.registrar, &mut self.authorizer, &mut self.issuer), prepared) {
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
                         ("redirect_url", EXAMPLE_REDIRECT_URL)]
            .iter().as_single_value_query()),
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
                         ("redirect_url", EXAMPLE_REDIRECT_URL)]
            .iter().as_single_value_query()),
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
                         ("redirect_url", EXAMPLE_REDIRECT_URL)]
            .iter().as_single_value_query()),
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
                         ("redirect_url", EXAMPLE_REDIRECT_URL)]
            .iter().as_single_value_query()),
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
                         ("redirect_url", EXAMPLE_REDIRECT_URL)]
            .iter().as_single_value_query()),
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
                         ("redirect_url", EXAMPLE_REDIRECT_URL)]
            .iter().as_single_value_query()),
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
                         ("redirect_url", EXAMPLE_REDIRECT_URL)]
            .iter().as_single_value_query()),
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
                         ("redirect_url", EXAMPLE_REDIRECT_URL)]
            .iter().as_single_value_query()),
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
                         ("redirect_url", "https://wrong.client.example/endpoint")]
            .iter().as_single_value_query()),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(wrong_redirection);
}

#[test]
fn access_request_invalid_redirection() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to get an access token with a redirection url which is not an url
    let invalid_redirection = CraftedRequest {
        query: None,
        urlbody: Some(vec![("grant_type", "authorization_code"),
                         ("code", &setup.authtoken),
                         ("redirect_url", "notanurl\x0Abogus\\")]
            .iter().as_single_value_query()),
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
                         ("redirect_url", EXAMPLE_REDIRECT_URL)]
            .iter().as_single_value_query()),
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
            ("redirect_url", EXAMPLE_REDIRECT_URL)]
        .iter().as_single_value_query();
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
                         ("redirect_url", EXAMPLE_REDIRECT_URL)]
            .iter().as_single_value_query()),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(wrong_grant_type);
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
        use primitives::issuer::Issuer;

        // Ensure that valid tokens are 16 bytes long, so we can craft an invalid one
        let mut issuer = TokenMap::new(RandomGenerator::new(16));

        let authtoken = issuer.issue(GrantRequest {
            client_id: EXAMPLE_CLIENT_ID,
            owner_id: EXAMPLE_OWNER_ID,
            redirect_url: &EXAMPLE_REDIRECT_URL.parse().unwrap(),
            scope: &"legit needed andmore".parse().unwrap(),
        });

        let wrong_scope_token = issuer.issue(GrantRequest {
            client_id: EXAMPLE_CLIENT_ID,
            owner_id: EXAMPLE_OWNER_ID,
            redirect_url: &EXAMPLE_REDIRECT_URL.parse().unwrap(),
            scope: &"wrong needed".parse().unwrap(),
        });

        let small_scope_token = issuer.issue(GrantRequest {
            client_id: EXAMPLE_CLIENT_ID,
            owner_id: EXAMPLE_OWNER_ID,
            redirect_url: &EXAMPLE_REDIRECT_URL.parse().unwrap(),
            scope: &"legit".parse().unwrap(),
        });

        ResourceSetup {
            issuer,
            authtoken: authtoken.token,
            wrong_scope_token: wrong_scope_token.token,
            small_scope_token: small_scope_token.token,
            resource_scope: ["needed legit".parse().unwrap()],
        }
    }

    fn test_access_error(&mut self, mut req: CraftedRequest) {
        let prepared = AccessFlow::prepare(&mut req).expect("Failed access preparation");
        match AccessFlow::handle(GuardRef::with(&mut self.issuer, &self.resource_scope), prepared) {
            Ok(resp) => panic!("Expected an error instead of {:?}", resp),
            Err(_) => (),
        }
    }
}

#[test]
fn resource_no_authorization() {
    // Does not have any authorization
    let no_authorization = CraftedRequest {
        query: None,
        urlbody: None,
        auth: None
    };

    ResourceSetup::new().test_access_error(no_authorization);
}

#[test]
fn resource_invalid_token() {
    // Does not have any authorization
    let invalid_token = CraftedRequest {
        query: None,
        urlbody: None,
        auth: Some("Bearer ThisisnotavalidtokenTooLong".to_string())
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
