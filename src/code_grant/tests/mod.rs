use super::frontend::*;
use primitives::generator::TokenGenerator;
use primitives::registrar::PreGrant;
use primitives::grant::Grant;

use std::borrow::Cow;
use std::collections::HashMap;

use url::Url;

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

    fn query(&mut self) -> Result<QueryParameter, ()> {
        self.query.as_ref()
            .map(|params|
                QueryParameter::MultiValue(
                    MultiValueQuery::StringValues(
                        Cow::Borrowed(params))))
            .ok_or(())
    }

    fn urlbody(&mut self) -> Result<QueryParameter, ()> {
        self.urlbody.as_ref()
            .map(|params|
                QueryParameter::MultiValue(
                    MultiValueQuery::StringValues(
                        Cow::Borrowed(params))))
            .ok_or(())
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

    fn redirect_error(target: ErrorRedirect) -> Result<Self, OAuthError> {
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
    fn generate(&self, _grant: &Grant) -> Result<String, ()> {
        Ok(self.0.clone())
    }
}

struct Allow(String);
struct Deny;

impl OwnerAuthorizer<CraftedRequest> for Allow {
    fn check_authorization(self, _: CraftedRequest, _: &PreGrant)
    -> OwnerAuthorization<CraftedResponse> {
        OwnerAuthorization::Authorized(self.0.clone())
    }
}

impl OwnerAuthorizer<CraftedRequest> for Deny {
    fn check_authorization(self, _: CraftedRequest, _: &PreGrant)
    -> OwnerAuthorization<CraftedResponse> {
        OwnerAuthorization::Denied
    }
}

impl<'l> OwnerAuthorizer<CraftedRequest> for &'l Allow {
    fn check_authorization(self, _: CraftedRequest, _: &PreGrant)
    -> OwnerAuthorization<CraftedResponse> {
        OwnerAuthorization::Authorized(self.0.clone())
    }
}

impl<'l> OwnerAuthorizer<CraftedRequest> for &'l Deny {
    fn check_authorization(self, _: CraftedRequest, _: &PreGrant)
    -> OwnerAuthorization<CraftedResponse> {
        OwnerAuthorization::Denied
    }
}

trait ToSingleValueQuery {
    fn to_single_value_query(self) -> HashMap<String, Vec<String>>;
}

impl<'r, I, K, V> ToSingleValueQuery for I where
    I: Iterator<Item=&'r (K, V)>,
    K: AsRef<str> + 'r,
    V: AsRef<str> + 'r {
    fn to_single_value_query(self) -> HashMap<String, Vec<String>> {
        self.map(|&(ref k, ref v)| (k.as_ref().to_string(), vec![v.as_ref().to_string()])).collect()
    }
}

pub mod defaults {
    pub const EXAMPLE_CLIENT_ID: &str = "ClientId";
    pub const EXAMPLE_OWNER_ID: &str = "Owner";
    pub const EXAMPLE_PASSPHRASE: &str = "VGhpcyBpcyBhIHZlcnkgc2VjdXJlIHBhc3NwaHJhc2UK";
    pub const EXAMPLE_REDIRECT_URI: &str = "https://client.example/endpoint";
    pub const EXAMPLE_SCOPE: &str = "example default";
}

/// Test the authorization code flow.
mod authorization_code;
/// Test the access token flow.
mod access_token;
/// Test the guard flow.
mod resource_guard;
/// Test functionality of pkce.
mod pkce;
