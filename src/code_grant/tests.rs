use super::frontend::*;
use super::backend::ErrorUrl;
use std::collections::HashMap;
use url::Url;

struct CraftedRequest {
    query: Option<HashMap<String, Vec<String>>>,
    urlbody: Option<HashMap<String, Vec<String>>>,
}

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

    fn query(&mut self) -> Result<HashMap<String, Vec<String>>, ()> {
        self.query.clone().ok_or(())
    }

    fn urlbody(&mut self) -> Result<&HashMap<String, Vec<String>>, ()> {
        self.urlbody.as_ref().ok_or(())
    }
}

impl WebResponse for CraftedResponse {
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
