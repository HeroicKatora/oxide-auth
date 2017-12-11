use super::frontend::*;
use super::backend::{CodeRef, ErrorUrl, IssuerRef, GuardRef};
use primitives::authorizer::Storage;
use primitives::generator::TokenGenerator;
use primitives::issuer::TokenMap;
use primitives::registrar::{Client, ClientMap, PreGrant};
use primitives::scope::Scope;
use primitives::grant::GrantRef;

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

struct SimpleConfidentialSetup {
    registrar: ClientMap,
    authorizer: Storage<TestGenerator>,
}

const EXAMPLE_CLIENT_ID: &str = "ClientId";
const EXAMPLE_OWNER_ID: &str = "Owner";
const EXAMPLE_REDIRECT_URL: &str = "https://client.example/endpoint";
const EXAMPLE_PASSPHRASE: &str = "VGhpcyBpcyBhIHZlcnkgc2VjdXJlIHBhc3NwaHJhc2UK";

impl SimpleConfidentialSetup {
    fn new() -> SimpleConfidentialSetup {
        let mut registrar = ClientMap::new();
        let authorizer = Storage::new(TestGenerator("AuthToken".to_string()));

        let client = Client::confidential(EXAMPLE_CLIENT_ID,
            Url::parse(EXAMPLE_REDIRECT_URL).unwrap(), "default".parse().unwrap(),
            EXAMPLE_PASSPHRASE.as_bytes());
        registrar.register_client(client);
        SimpleConfidentialSetup {
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
        auth: Some("Basic ".to_string() + client_id + ":" + &base64::encode(passphrase)),
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
fn access_request_silent_missing_client() {
    let missing_client = CraftedRequest {
        query: Some(vec![("response_type", "code")].iter().as_single_value_query()),
        urlbody: None,
        auth: None,
    };

    SimpleConfidentialSetup::new().test_silent_error(missing_client);
}

#[test]
fn access_request_silent_unknown_client() {
    // The client_id is not registered
    let unknown_client = CraftedRequest {
        query: Some(vec![("response_type", "code"),
                         ("client_id", "SomeOtherClient"),
                         ("redirect_url", "https://wrong.client.example/endpoint")]
            .iter().as_single_value_query()),
        urlbody: None,
        auth: None,
    };

    SimpleConfidentialSetup::new().test_silent_error(unknown_client);
}

#[test]
fn access_request_silent_mismatching_redirect() {
    // The redirect_url does not match
    let mismatching_redirect = CraftedRequest {
        query: Some(vec![("response_type", "code"),
                         ("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_url", "https://wrong.client.example/endpoint")]
            .iter().as_single_value_query()),
        urlbody: None,
        auth: None,
    };

    SimpleConfidentialSetup::new().test_silent_error(mismatching_redirect);
}

#[test]
fn access_request_silent_invalid_redirect() {
    // The redirect_url is not an url
    let invalid_redirect = CraftedRequest {
        query: Some(vec![("response_type", "code"),
                         ("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_url", "notanurl\x0Abogus\\")]
            .iter().as_single_value_query()),
        urlbody: None,
        auth: None,
    };

    SimpleConfidentialSetup::new().test_silent_error(invalid_redirect);
}

#[test]
fn access_request_error_denied() {
    // Used in conjunction with a denying authorization handler below
    let denied_request = CraftedRequest {
        query: Some(vec![("response_type", "code"),
                         ("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_url", EXAMPLE_REDIRECT_URL)]
            .iter().as_single_value_query()),
        urlbody: None,
        auth: None,
    };

    SimpleConfidentialSetup::new().test_error_redirect(denied_request, &Deny);
}

#[test]
fn access_request_error_unsupported_method() {
    // Requesting an authorization token for a method other than code
    let unsupported_method = CraftedRequest {
        query: Some(vec![("response_type", "other_method"),
                         ("client_id", EXAMPLE_CLIENT_ID),
                         ("redirect_url", EXAMPLE_REDIRECT_URL)]
            .iter().as_single_value_query()),
        urlbody: None,
        auth: None,
    };

    SimpleConfidentialSetup::new().test_error_redirect(unsupported_method,
        &Allow(EXAMPLE_OWNER_ID.to_string()));
}

#[test]
fn access_request_error_malformed_scope() {
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

    SimpleConfidentialSetup::new().test_error_redirect(malformed_scope,
        &Allow(EXAMPLE_OWNER_ID.to_string()));
}
