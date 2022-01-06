use crate::WebError;
use axum::{
    response::{IntoResponse, Response},
    http::{
        StatusCode,
        header::{self, HeaderMap, HeaderValue},
    },
};
use oxide_auth::frontends::dev::{WebResponse, Url};

#[derive(Default, Clone, Debug)]
/// Type implementing `WebResponse` and `IntoResponse` for use in route handlers
pub struct OAuthResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Option<String>,
}

impl OAuthResponse {
    /// Set the `ContentType` header on a response
    pub fn content_type(mut self, content_type: &str) -> Result<Self, WebError> {
        self.headers
            .insert(header::CONTENT_TYPE, content_type.try_into()?);
        Ok(self)
    }

    /// Set the body for the response
    pub fn body(mut self, body: &str) -> Self {
        self.body = Some(body.to_owned());
        self
    }
}

impl WebResponse for OAuthResponse {
    type Error = WebError;

    fn ok(&mut self) -> Result<(), Self::Error> {
        self.status = StatusCode::OK;
        Ok(())
    }

    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> {
        self.status = StatusCode::FOUND;
        self.headers.insert(header::LOCATION, url.as_ref().try_into()?);
        Ok(())
    }

    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.status = StatusCode::BAD_REQUEST;
        Ok(())
    }

    fn unauthorized(&mut self, kind: &str) -> Result<(), Self::Error> {
        self.status = StatusCode::UNAUTHORIZED;
        self.headers.insert(header::WWW_AUTHENTICATE, kind.try_into()?);
        Ok(())
    }

    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> {
        self.body = Some(text.to_owned());
        self.headers
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        Ok(())
    }

    fn body_json(&mut self, json: &str) -> Result<(), Self::Error> {
        self.body = Some(json.to_owned());
        self.headers
            .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Ok(())
    }
}

impl IntoResponse for OAuthResponse {
    fn into_response(self) -> Response {
        (self.status, self.headers, self.body.unwrap_or_default()).into_response()
    }
}
