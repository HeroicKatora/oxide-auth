use std::collections::HashMap;

use code_grant::endpoint::{NormalizedParameter, OAuthError, QueryParameter, WebRequest, WebResponse};

use url::Url;

use super::actix_web::{HttpMessage, HttpRequest, HttpResponse};
use super::actix_web::http::header;

pub(super) struct ResolvedRequest {
    authorization: Result<Option<String>, ()>,
    query: Option<NormalizedParameter>,
    body: Option<NormalizedParameter>,
}

impl ResolvedRequest {
    pub fn headers_only(request: HttpRequest) -> Self {
        let authorization = match request.headers().get("Authorization").map(|header| header.to_str()) {
            None => Ok(None),
            Some(Ok(as_str)) => Ok(Some(as_str.to_string())),
            Some(Err(_)) => Err(())
        };

        let query = request
            .query()
            .iter()
            .map(|(key, val)| (key.clone(), val.clone()))
            .collect();

        ResolvedRequest {
            authorization: authorization,
            query: Some(query),
            body: None,
        }
    }

    pub fn with_body(request: HttpRequest, body: HashMap<String, String>) -> Self {
        let mut resolved = Self::headers_only(request);
        resolved.body = Some(body);
        resolved
    }
}

