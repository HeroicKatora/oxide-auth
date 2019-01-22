//! Offers bindings for the code_grant module with iron servers.
//!
//! ## Hello world
//!
extern crate iron;

use std::borrow::Cow;

use endpoint::{OAuthError, QueryParameter, WebRequest, WebResponse};
use frontends::simple::endpoint::Error as SimpleError;

use self::iron::{Request, Response};
use self::iron::error::IronError;
use self::iron::headers;
use self::iron::status::Status;
use url::Url;

/// Errors while decoding requests.
pub enum Error { 
    /// Generally describes a malformed request.
    BadRequest,
}

/// Requests are handed as mutable reference to the underlying object.
impl<'a, 'b, 'c: 'b> WebRequest for &'a mut Request<'b, 'c> {
    type Response = Response;
    type Error = Error;

    fn query(&mut self) -> Result<Cow<QueryParameter + 'static>, Self::Error> {
        serde_urlencoded::from_str(self.url.query().unwrap_or(""))
            .map_err(|_| Error::BadRequest)
            .map(Cow::Owned)
    }

    fn urlbody(&mut self) -> Result<Cow<QueryParameter + 'static>, Self::Error> {
        let content_type = self.headers.get::<headers::ContentType>();
        let formatted = content_type
            .map(|ct| ct == &headers::ContentType::form_url_encoded())
            .unwrap_or(false);
        if !formatted {
            return Err(Error::BadRequest)
        }

        serde_urlencoded::from_reader(&mut self.body)
            .map_err(|_| Error::BadRequest)
            .map(Cow::Owned)
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, Self::Error> {
        // Get the raw header.
        match self.headers.get::<headers::Authorization<String>>() {
            None => Ok(None),
            Some(header) => Ok(Some(Cow::Borrowed(&header.0))),
        }
    }
}

impl WebResponse for Response {
    type Error = Error;

    fn ok(&mut self) -> Result<(), Self::Error> { 
        self.status = Some(Status::Ok);
        Ok(())
    }

    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> { 
        self.status = Some(Status::Found);
        self.headers.set(headers::Location(url.into_string()));
        Ok(())
    }

    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.status = Some(Status::BadRequest);
        Ok(())
    }

    fn unauthorized(&mut self, header_value: &str) -> Result<(), Self::Error> { 
        self.status = Some(Status::Unauthorized);
        let value_owned = header_value.as_bytes().to_vec();
        self.headers.set_raw("WWW-Authenticate", vec![value_owned]);
        Ok(())
    }

    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> { 
        self.headers.set(headers::ContentType::plaintext());
        self.body = Some(Box::new(text.to_string()));
        Ok(())
    }

    fn body_json(&mut self, data: &str) -> Result<(), Self::Error> { 
        self.headers.set(headers::ContentType::json());
        self.body = Some(Box::new(data.to_string()));
        Ok(())
    }
}

// impl ErrorTrait for OAuthError { }

impl<'a, 'b, 'c: 'b> From<SimpleError<&'a mut Request<'b, 'c>>> for IronError {
    fn from(error: SimpleError<&'a mut Request<'b, 'c>>) -> Self {
        let as_oauth = match error {
            SimpleError::Web(Error::BadRequest) => OAuthError::BadRequest,
            SimpleError::OAuth(oauth) => oauth,
        };
        
        let status = match as_oauth {
            OAuthError::BadRequest => Status::BadRequest,
            OAuthError::DenySilently => Status::BadRequest,
            OAuthError::PrimitiveError => Status::InternalServerError,
        };

        IronError::new(as_oauth, status)
    }
}
