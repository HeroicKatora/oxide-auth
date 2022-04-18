use poem::http::{header, HeaderMap, HeaderValue, StatusCode};
use poem::{IntoResponse, Response, ResponseBuilder};
use oxide_auth::endpoint::WebResponse;
use oxide_auth::frontends::dev::Url;
use crate::error::OxidePoemError;

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
    type Error = OxidePoemError;

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

    fn unauthorized(&mut self, header_value: &str) -> Result<(), Self::Error> {
        self.status = StatusCode::UNAUTHORIZED;
        self.headers.insert(header::WWW_AUTHENTICATE, header_value.try_into()?);
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
    fn into_response(mut self) -> Response {
        let mut response = Response::builder()
            .status(self.status)
            .body(self.body)
            .into_response();
        {
            let mut headers = response.headers_mut();
            for (k, v) in self.headers {
                headers.insert(k, v);
            }

        }
        response
    }
}
