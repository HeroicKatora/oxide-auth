use poem::{
    http::{
        Extensions,
        header::{InvalidHeaderValue, CONTENT_TYPE, LOCATION, WWW_AUTHENTICATE},
        HeaderMap, HeaderValue, StatusCode, Version,
    },
    Body, IntoResponse, Response, ResponseParts,
};
use oxide_auth::{endpoint::WebResponse, frontends::dev::Url};
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
    /// # Errors
    /// In case the `content_type` cannot be parsed, this will return an [`OxidePoemError::Header(_)`]
    pub fn content_type(mut self, content_type: &str) -> Result<Self, OxidePoemError> {
        // the explicit typedef is probably unnecessary but my IDE is giving me errors otherwise so /shrug/
        self.headers.insert(
            CONTENT_TYPE,
            content_type
                .parse()
                .map_err(|err: InvalidHeaderValue| OxidePoemError::Header(err.to_string()))?,
        );
        Ok(self)
    }

    /// Set the body for the response
    #[must_use]
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
        self.headers.insert(
            LOCATION,
            HeaderValue::from_str(url.as_str())
                .map_err(|header_err| OxidePoemError::Header(header_err.to_string()))?, // This is an `Infallible` type!
        );
        Ok(())
    }

    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.status = StatusCode::BAD_REQUEST;
        Ok(())
    }

    fn unauthorized(&mut self, header_value: &str) -> Result<(), Self::Error> {
        self.status = StatusCode::UNAUTHORIZED;
        self.headers.insert(
            WWW_AUTHENTICATE,
            header_value
                .parse()
                .map_err(|err: InvalidHeaderValue| OxidePoemError::Header(err.to_string()))?,
        );
        Ok(())
    }

    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> {
        self.body = Some(text.to_owned());
        self.headers
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        Ok(())
    }

    fn body_json(&mut self, json: &str) -> Result<(), Self::Error> {
        self.body = Some(json.to_owned());
        self.headers
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Ok(())
    }
}

impl IntoResponse for OAuthResponse {
    fn into_response(self) -> Response {
        Response::from_parts(
            ResponseParts {
                status: self.status,
                version: Version::default(),
                headers: self.headers,
                extensions: Extensions::default(),
            },
            match self.body {
                Some(content) => Body::from(content),
                None => Body::empty(),
            },
        )
    }
}
