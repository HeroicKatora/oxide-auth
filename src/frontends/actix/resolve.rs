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

enum ResponseContent {
    Redirect(Url),
    Json(String),
    Text(String),
    Html(String),
}

enum ResponseKind {
    Ok(ResponseContent),
    ClientError(ResponseContent),
    Unauthorized(ResponseContent),
    Authorization(ResponseContent, String),
    InternalError,
}

/// An http response replacement that can be sent as an actix message.
///
/// This is the generic answer to oauth authorization code and bearer token requests.
pub struct ResolvedResponse {
    inner: ResponseKind,
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
    type Response = ResolvedResponse;

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

impl WebResponse for ResolvedResponse {
    type Error = OAuthError;

    fn redirect(url: Url) -> Result<Self, Self::Error> {
        Ok(ResponseKind::Ok(ResponseContent::Redirect(url)).wrap())
    }

    fn text(text: &str) -> Result<Self, Self::Error> {
        Ok(ResponseKind::Ok(ResponseContent::Text(text.to_owned())).wrap())
    }

    fn json(data: &str) -> Result<Self, Self::Error> {
        Ok(ResponseKind::Ok(ResponseContent::Json(data.to_owned())).wrap())
    }

    fn as_client_error(self) -> Result<Self, Self::Error> {
        match self.inner {
            ResponseKind::Ok(response)
            | ResponseKind::ClientError(response)
            | ResponseKind::Unauthorized(response)
            | ResponseKind::Authorization(response, _)
                => Ok(ResponseKind::ClientError(response).wrap()),
            ResponseKind::InternalError
                => Ok(ResponseKind::InternalError.wrap()),
        }
    }

    fn as_unauthorized(self) -> Result<Self, Self::Error> {
        match self.inner {
            ResponseKind::Ok(response)
            | ResponseKind::ClientError(response)
            | ResponseKind::Unauthorized(response)
            | ResponseKind::Authorization(response, _)
                => Ok(ResponseKind::Unauthorized(response).wrap()),
            ResponseKind::InternalError
                => Ok(ResponseKind::InternalError.wrap()),
        }
    }

    fn with_authorization(self, kind: &str) -> Result<Self, Self::Error> {
        match self.inner {
            ResponseKind::Ok(response)
            | ResponseKind::ClientError(response)
            | ResponseKind::Unauthorized(response)
            | ResponseKind::Authorization(response, _)
                => Ok(ResponseKind::Authorization(response, kind.to_owned()).wrap()),
            ResponseKind::InternalError
                => Ok(ResponseKind::InternalError.wrap()),
        }
    }
}

impl ResponseContent {
    fn into(self) -> HttpResponse {
        match self {
            ResponseContent::Redirect(url) =>
                HttpResponse::Found()
                    .header("Location", url.as_str())
                    .finish(),
            ResponseContent::Text(text) =>
                HttpResponse::Ok()
                    .content_type("text/plain")
                    .body(text),
            ResponseContent::Json(json) =>
                HttpResponse::Ok()
                    .content_type("application/json")
                    .body(json),
            ResponseContent::Html(html) =>
                HttpResponse::Ok()
                    .content_type("text/html")
                    .body(html),
        }
    }
}

impl ResponseKind {
    fn into(self) -> HttpResponse {
        match self {
            ResponseKind::Ok(response) => response.into(),
            ResponseKind::ClientError(response) => {
                let mut response = response.into();
                response.status_mut().clone_from(&StatusCode::BAD_REQUEST);
                response
            },
            ResponseKind::Unauthorized(response) => {
                let mut response = response.into();
                response.status_mut().clone_from(&StatusCode::UNAUTHORIZED);
                response
            },
            ResponseKind::Authorization(response, kind) => {
                let mut response = response.into();
                response.status_mut().clone_from(&StatusCode::UNAUTHORIZED);
                let header_content = kind.parse().unwrap();
                response.headers_mut().insert("WWW-Authenticate", header_content);
                response
            },
            ResponseKind::InternalError => {
                HttpResponse::InternalServerError().finish()
            },
        }
    }

    fn wrap(self) -> ResolvedResponse {
        ResolvedResponse {
            inner: self,
        }
    }
}

impl ResolvedResponse {
    /// An html response.
    pub fn html(content: &str) -> ResolvedResponse {
        ResolvedResponse {
            inner: ResponseKind::Ok(ResponseContent::Html(content.to_owned())),
        }
    }

    /// Convert the response into an http response.
    pub fn actix_response(self) -> HttpResponse {
        self.inner.into()
    }

    /// An instance representing an internal error.
    ///
    /// While not created by the usual WebResponse methods, this makes it possible to uniformly
    /// build a response based on an OAuthError.
    pub fn internal_error() -> Self {
        ResolvedResponse {
            inner: ResponseKind::InternalError,
        }
    }

    /// Create a response to the error, using the internal error representation.
    pub fn response_or_error(error: OAuthError) -> Self {
        error.response_or_else(Self::internal_error)
    }
}

impl From<ResolvedResponse> for HttpResponse {
    fn from(resolved: ResolvedResponse) -> Self {
        resolved.actix_response()
    }
}
