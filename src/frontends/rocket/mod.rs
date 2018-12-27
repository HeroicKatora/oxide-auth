//! Adaptions and integration for rocket.
extern crate rocket;
extern crate serde_urlencoded;

use std::io::Cursor;

use self::rocket::{Request, Response};
use self::rocket::http::{ContentType, Status};
use self::rocket::http::hyper::header;
use self::rocket::request::FromRequest;
use self::rocket::outcome::Outcome;

use code_grant::endpoint::{NormalizedParameter, WebRequest, WebResponse};
use frontends::dev::*;

pub use frontends::simple::endpoint::Generic;
pub use frontends::simple::request::NoError;

pub struct OAuthRequest<'a, 'r> {
    request: &'a Request<'r>,
    query: Result<NormalizedParameter, WebError>,
    body: Result<NormalizedParameter, WebError>,
}

#[derive(Clone, Copy, Debug)]
pub enum WebError {
    /// A parameter was encoded incorrectly.
    ///
    /// This may happen for example due to a query parameter that is not valid utf8 when the query
    /// parameters are necessary for OAuth processing.
    Encoding,

    /// Form data was requested but the request was not a form.
    NotAForm,
}

impl<'a, 'r> OAuthRequest<'a, 'r> {
    pub fn new(request: &'a Request<'r>) -> Self {
        let query = request.uri().query().unwrap_or("");
        let query = match serde_urlencoded::from_str::<Vec<(String, String)>>(query) {
            Ok(query) => Ok(query.into_iter().collect()),
            Err(_) => Err(WebError::Encoding),
        };

        let body = match request.content_type() {
            Some(ct) if *ct == ContentType::Form => {
                Ok(NormalizedParameter::default())
            },
            _ => Err(WebError::NotAForm),
        };

        OAuthRequest {
            request,
            query,
            body,
        }
    }
}

impl<'a, 'r> WebRequest for OAuthRequest<'a, 'r> {
    type Error = WebError;
    type Response = Response<'r>;

    fn query(&mut self) -> Result<Cow<QueryParameter + 'static>, Self::Error> {
        match self.query.as_ref() {
            Ok(query) => Ok(Cow::Borrowed(query as &QueryParameter)),
            Err(err) => Err(*err),
        }
    }

    fn urlbody(&mut self) ->  Result<Cow<QueryParameter + 'static>, Self::Error> {
        match self.body.as_ref() {
            Ok(body) => Ok(Cow::Borrowed(body as &QueryParameter)),
            Err(err) => Err(*err),
        }
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, Self::Error> {
        let mut all = self.request.headers().get("Authorization");
        let optional = all.next();

        // Duplicate auth header, just treat it as no authorization.
        if let Some(_) = all.next() {
            Ok(None)
        } else {
            Ok(optional.map(Cow::Borrowed))
        }
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

impl<'a, 'r> FromRequest<'a, 'r> for OAuthRequest<'a, 'r> {
    type Error = NoError;

    fn from_request(request: &'a Request<'r>) -> Outcome<Self, (Status, Self::Error), ()> {
        Outcome::Success(Self::new(request))
    }
}

