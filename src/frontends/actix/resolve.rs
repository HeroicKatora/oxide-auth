use std::borrow::Cow;
use std::collections::HashMap;

use code_grant::frontend::{SingleValueQuery, QueryParameter, WebRequest, WebResponse};
use code_grant::frontend::OAuthError;

use url::Url;

use super::actix_web::{HttpMessage, HttpRequest, HttpResponse};
use super::actix_web::http::StatusCode;

pub(super) struct ResolvedRequest {
    authorization: Result<Option<String>, ()>,
    query: Option<HashMap<String, String>>,
    body: Option<HashMap<String, String>>,
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
            .map(|&(ref key, ref val)| (key.clone().into_owned(), val.clone().into_owned()))
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

impl WebRequest for ResolvedRequest {
    type Error = OAuthError;
    type Response = HttpResponse;

     fn query(&mut self) -> Result<QueryParameter, ()> {
         self.query.as_ref().map(|query| QueryParameter::SingleValue(
             SingleValueQuery::StringValue(Cow::Borrowed(query))))
             .ok_or(())
     }

     fn urlbody(&mut self) -> Result<QueryParameter, ()> {
         self.body.as_ref().map(|body| QueryParameter::SingleValue(
             SingleValueQuery::StringValue(Cow::Borrowed(body))))
             .ok_or(())
     }

     fn authheader(&mut self) -> Result<Option<Cow<str>>, ()>{
         match &self.authorization {
             &Ok(Some(ref string)) => Ok(Some(Cow::Borrowed(string))),
             &Ok(None) => Ok(None),
             &Err(_) => Err(())
         }
     }
}

impl WebResponse for HttpResponse {
    type Error = OAuthError;

    fn redirect(url: Url) -> Result<Self, Self::Error> {
        Ok(HttpResponse::Found()
            .header("Location", url.as_str())
            .finish())
    }

    fn text(text: &str) -> Result<Self, Self::Error> {
        Ok(HttpResponse::Ok()
            .content_type("text/plain")
            .body(text.to_owned()))
    }

    fn json(data: &str) -> Result<Self, Self::Error> {
        Ok(HttpResponse::Ok()
            .content_type("application/json")
            .body(data.to_owned()))
    }

    fn as_client_error(mut self) -> Result<Self, Self::Error> {
        self.status_mut().clone_from(&StatusCode::BAD_REQUEST);
        Ok(self)
    }

    fn as_unauthorized(mut self) -> Result<Self, Self::Error> {
        self.status_mut().clone_from(&StatusCode::UNAUTHORIZED);
        Ok(self)
    }

    fn with_authorization(mut self, kind: &str) -> Result<Self, Self::Error> {
        self.status_mut().clone_from(&StatusCode::UNAUTHORIZED);
        let header_content = kind.parse().map_err(|_| OAuthError::PrimitiveError)?;
        self.headers_mut().insert("WWW-Authenticate", header_content);
        Ok(self)
    }
}
