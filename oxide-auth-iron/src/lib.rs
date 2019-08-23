//! Offers bindings for the code_grant module with iron servers.
//!
//! ## Hello world
//!
extern crate iron;
extern crate oxide_auth_core;
extern crate serde_urlencoded;
extern crate url;

use std::borrow::Cow;

use iron::error::IronError;
use iron::headers;
use iron::status::Status;
use iron::{Request, Response};
use oxide_auth_core::endpoint::{
    OAuthError as EndpointError, QueryParameter, WebRequest, WebResponse,
};
use oxide_auth_core::frontends::simple::endpoint::Error as SimpleError;
use url::Url;

/// Errors while decoding requests.
pub enum Error {
    /// Generally describes a malformed request.
    BadRequest,
}

#[derive(Debug)]
pub struct OAuthRequest<'a, 'b, 'c: 'b>(pub &'a mut Request<'b, 'c>);

impl<'a, 'b, 'c: 'b> OAuthRequest<'a, 'b, 'c> {
    pub fn from_request(request: &'a mut Request<'b, 'c>) -> Self {
        OAuthRequest(request)
    }
}

impl<'a, 'b, 'c: 'b> From<&'a mut Request<'b, 'c>> for OAuthRequest<'a, 'b, 'c> {
    fn from(r: &'a mut Request<'b, 'c>) -> Self {
        OAuthRequest::from_request(r)
    }
}

/// Requests are handed as mutable reference to the underlying object.
impl<'a, 'b, 'c: 'b> WebRequest for OAuthRequest<'a, 'b, 'c> {
    type Response = OAuthResponse;
    type Error = Error;

    fn query(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
        serde_urlencoded::from_str(self.0.url.query().unwrap_or(""))
            .map_err(|_| Error::BadRequest)
            .map(Cow::Owned)
    }

    fn urlbody(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
        let content_type = self.0.headers.get::<headers::ContentType>();
        let formatted = content_type
            .map(|ct| ct == &headers::ContentType::form_url_encoded())
            .unwrap_or(false);
        if !formatted {
            return Err(Error::BadRequest);
        }

        serde_urlencoded::from_reader(&mut self.0.body)
            .map_err(|_| Error::BadRequest)
            .map(Cow::Owned)
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, Self::Error> {
        // Get the raw header.
        match self.0.headers.get::<headers::Authorization<String>>() {
            None => Ok(None),
            Some(header) => Ok(Some(Cow::Borrowed(&header.0))),
        }
    }
}

#[derive(Debug)]
pub struct OAuthResponse(pub Response);

impl OAuthResponse {
    pub fn new() -> Self {
        OAuthResponse(Response::new())
    }

    pub fn from_response(response: Response) -> Self {
        OAuthResponse(response)
    }
}

impl From<Response> for OAuthResponse {
    fn from(r: Response) -> Self {
        OAuthResponse::from_response(r)
    }
}

impl Into<Response> for OAuthResponse {
    fn into(self) -> Response {
        self.0
    }
}

impl WebResponse for OAuthResponse {
    type Error = Error;

    fn ok(&mut self) -> Result<(), Self::Error> {
        self.0.status = Some(Status::Ok);
        Ok(())
    }

    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> {
        self.0.status = Some(Status::Found);
        self.0.headers.set(headers::Location(url.into_string()));
        Ok(())
    }

    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.0.status = Some(Status::BadRequest);
        Ok(())
    }

    fn unauthorized(&mut self, header_value: &str) -> Result<(), Self::Error> {
        self.0.status = Some(Status::Unauthorized);
        let value_owned = header_value.as_bytes().to_vec();
        self.0
            .headers
            .set_raw("WWW-Authenticate", vec![value_owned]);
        Ok(())
    }

    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> {
        self.0.headers.set(headers::ContentType::plaintext());
        self.0.body = Some(Box::new(text.to_string()));
        Ok(())
    }

    fn body_json(&mut self, data: &str) -> Result<(), Self::Error> {
        self.0.headers.set(headers::ContentType::json());
        self.0.body = Some(Box::new(data.to_string()));
        Ok(())
    }
}

#[derive(Debug)]
pub struct OAuthError(pub IronError);

impl From<IronError> for OAuthError {
    fn from(e: IronError) -> Self {
        OAuthError(e)
    }
}

impl Into<IronError> for OAuthError {
    fn into(self) -> IronError {
        self.0
    }
}

impl<'a, 'b, 'c: 'b> From<SimpleError<OAuthRequest<'a, 'b, 'c>>> for OAuthError {
    fn from(error: SimpleError<OAuthRequest<'a, 'b, 'c>>) -> Self {
        let as_oauth = match error {
            SimpleError::Web(Error::BadRequest) => EndpointError::BadRequest,
            SimpleError::OAuth(oauth) => oauth,
        };

        let status = match as_oauth {
            EndpointError::BadRequest => Status::BadRequest,
            EndpointError::DenySilently => Status::BadRequest,
            EndpointError::PrimitiveError => Status::InternalServerError,
        };

        OAuthError(IronError::new(as_oauth, status))
    }
}
