//! Adaptions and integration for rocket.
extern crate rocket;
extern crate serde_urlencoded;

mod failure;

use std::io::Cursor;
use std::marker::PhantomData;

use self::rocket::{Data, Request, Response};
use self::rocket::http::{ContentType, Status};
use self::rocket::http::hyper::header;
use self::rocket::request::FromRequest;
use self::rocket::response::{self, Responder};
use self::rocket::outcome::Outcome;

use endpoint::{NormalizedParameter, WebRequest, WebResponse};
use frontends::dev::*;

pub use frontends::simple::endpoint::Generic;
pub use frontends::simple::request::NoError;
pub use self::failure::OAuthFailure;

/// Request guard that also buffers OAuth data internally.
///
/// `WebRequest` etc. is implemented for the basic `rocket::Request<'r>` as well. Both have the
/// same error and result types but of course we can not simply implement the former as a request
/// guard with special semantics. Therefore, we wrap in here and at the same time buffer all the
/// computed state such as parameter checking and normalization.
pub struct OAuthRequest<'r> {
    auth: Option<String>,
    query: Result<NormalizedParameter, WebError>,
    body: Result<Option<NormalizedParameter>, WebError>,
    lifetime: PhantomData<&'r ()>,
}

/// Request error at the http layer.
///
/// For performance and consistency reasons, the processing of a request body and data is delayed
/// until it is actually required. This in turn means that some invalid requests will only be
/// caught during the OAuth process. The possible errors are collected in this type.
#[derive(Clone, Copy, Debug)]
pub enum WebError {
    /// A parameter was encoded incorrectly.
    ///
    /// This may happen for example due to a query parameter that is not valid utf8 when the query
    /// parameters are necessary for OAuth processing.
    Encoding,

    /// The body was needed but not provided.
    BodyNeeded,

    /// Form data was requested but the request was not a form.
    NotAForm,
}

impl<'r> OAuthRequest<'r> {
    /// Create the request data from request headers.
    ///
    /// Some oauth methods need additionally the body data which you can attach later.
    pub fn new<'a>(request: &'a Request<'r>) -> Self {
        let query = request.uri().query().unwrap_or("");
        let query = match serde_urlencoded::from_str(query) {
            Ok(query) => Ok(query),
            Err(_) => Err(WebError::Encoding),
        };

        let body = match request.content_type() {
            Some(ct) if *ct == ContentType::Form => Ok(None),
            _ => Err(WebError::NotAForm),
        };

        let mut all_auth = request.headers().get("Authorization");
        let optional = all_auth.next();

        // Duplicate auth header, just treat it as no authorization.
        let auth = if let Some(_) = all_auth.next() {
            None
        } else {
            optional.map(str::to_owned)
        };

        OAuthRequest {
            auth,
            query,
            body,
            lifetime: PhantomData,
        }
    }

    /// Provide the body of the request.
    ///
    /// Some, but not all operations, require reading their data from a urlencoded POST body. To
    /// simplify the implementation of primitives and handlers, this type is the central request
    /// type for both these use cases. When you forget to provide the body to a request, the oauth
    /// system will return an error the moment the request is used.
    pub fn add_body(&mut self, data: Data) {
        // Nothing to do if we already have a body, or already generated an error. This includes
        // the case where the content type does not indicate a form, as the error is silent until a
        // body is explicitely requested.
        if let Ok(None) = self.body {
            match serde_urlencoded::from_reader(data.open()) {
                Ok(query) => self.body = Ok(Some(query)),
                Err(_) => self.body = Err(WebError::Encoding),
            }
        }
    }
}

impl<'r> WebRequest for OAuthRequest<'r> {
    type Error = WebError;
    type Response = Response<'r>;

    fn query(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
        match self.query.as_ref() {
            Ok(query) => Ok(Cow::Borrowed(query as &dyn QueryParameter)),
            Err(err) => Err(*err),
        }
    }

    fn urlbody(&mut self) ->  Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
        match self.body.as_ref() {
            Ok(None) => Err(WebError::BodyNeeded),
            Ok(Some(body)) => Ok(Cow::Borrowed(body as &dyn QueryParameter)),
            Err(err) => Err(*err),
        }
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, Self::Error> {
        Ok(self.auth.as_ref().map(String::as_str).map(Cow::Borrowed))
    }
}

impl<'r> WebResponse for Response<'r> {
    type Error = WebError;

    fn ok(&mut self) -> Result<(), Self::Error> {
        self.set_status(Status::Ok);
        Ok(())
    }

    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> {
        self.set_status(Status::Found);
        self.set_header(header::Location(url.into_string()));
        Ok(())
    }

    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.set_status(Status::BadRequest);
        Ok(())
    }

    fn unauthorized(&mut self, kind: &str) -> Result<(), Self::Error> {
        self.set_status(Status::Unauthorized);
        self.set_raw_header("WWW-Authenticate", kind.to_owned());
        Ok(())
    }

    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> {
        self.set_sized_body(Cursor::new(text.to_owned()));
        self.set_header(ContentType::Plain);
        Ok(())
    }

    fn body_json(&mut self, data: &str) -> Result<(), Self::Error> {
        self.set_sized_body(Cursor::new(data.to_owned()));
        self.set_header(ContentType::JSON);
        Ok(())
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for OAuthRequest<'r> {
    type Error = NoError;

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, (Status, Self::Error), ()> {
        Outcome::Success(Self::new(request))
    }
}

impl<'r> Responder<'r> for WebError {
    fn respond_to(self, _: &Request) -> response::Result<'r> {
        match self {
            WebError::Encoding => Err(Status::BadRequest),
            WebError::NotAForm => Err(Status::BadRequest),
            WebError::BodyNeeded => Err(Status::InternalServerError),
        }
    }
}
