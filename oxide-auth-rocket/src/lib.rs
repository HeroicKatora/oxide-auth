//! Adaptions and integration for rocket.
#![warn(missing_docs)]

mod failure;

use std::io::Cursor;
use rocket::http::Header;
use std::marker::PhantomData;

use rocket::data::ByteUnit;
use rocket::{Data, Request, Response};
use rocket::http::{ContentType, Status};
use rocket::http::hyper::header;
use rocket::request::FromRequest;
use rocket::response::{self, Responder};
use rocket::outcome::Outcome;

use oxide_auth::endpoint::{NormalizedParameter, WebRequest, WebResponse};
use oxide_auth::frontends::dev::*;

pub use oxide_auth::frontends::simple::endpoint::Generic;
pub use oxide_auth::frontends::simple::request::NoError;
pub use self::failure::OAuthFailure;

/// Request guard that also buffers OAuth data internally.
pub struct OAuthRequest<'r> {
    auth: Option<String>,
    query: Result<NormalizedParameter, WebError>,
    body: Result<Option<NormalizedParameter>, WebError>,
    lifetime: PhantomData<&'r ()>,
}

/// Response type for Rocket OAuth requests
///
/// A simple wrapper type around a simple `rocket::Response<'r>` that implements `WebResponse`.
#[derive(Debug)]
pub struct OAuthResponse<'r>(Response<'r>);

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

    /// Failed to read the datastream into a string while attemting to call add_body
    DataStreamReadFailed,

    /// reached the default or  configured maximum data size limits while reading the datastream into a string and there is still data remaining
    ExceededDataLimits 

}

impl<'r> OAuthRequest<'r> {
    /// Create the request data from request headers.
    ///
    /// Some oauth methods need additionally the body data which you can attach later.
    pub fn new<'a>(request: &'a Request<'r>) -> Self {
        // rocket::http::uri::Query can no longer be constructed using the following line:
        // let query = request.uri().query().unwrap_or("");
        // request.uri().query() -> Option<rocket::http::uri::Query<'_>>
        // using query.as_str to preserve the original behavior
        let query = request.uri().query().map(|query| query.as_str()).unwrap_or("");
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
    pub async fn add_body(&mut self, data: Data<'_>,limits: Option<ByteUnit>) {
        // Nothing to do if we already have a body, or already generated an error. This includes
        // the case where the content type does not indicate a form, as the error is silent until a
        // body is explicitely requested.

        // jtmorrisbytes:
        // not sure whether this is the desired behavior, but
        // trying to prevent defining our own default here
        // https://api.rocket.rs/v0.5/rocket/data/struct.Limits
        // unsure whether to use FORM or DATA_FORM here. More research is required
        // in order to get the configured limits from request.rocket().limits(),
        // we need a reference to the request here.
        
        
        if let Ok(None) = self.body {
            // accepts the limit given to the function or uses the rocket configured default
            let limit = limits.unwrap_or(rocket::data::Limits::FORM);
            let data = data.open(limit);
            // jtmorrisbytes:
            // datastream has several options
            // 
            // we can stream the data into a file and read it from there
            // we can convert the datastream into a vector of bytes.
            // we can stream the stream into another vector of bytes
            // we can also convert the datastream into a string.
            // if we convert the datastream into a string, it will guarentee that the data is valid UTF-8
            // 
            // https://api.rocket.rs/v0.5/rocket/data/struct.DataStream
            // but std::io::read is no longer implemented
            // in favor of tokio::io::util::AsyncRead
            // 
            // I am going to read the data into a string, then serialize the data

            // try to read the data into a string. if it fails, set an error and retern early
            let capped_string = match data.into_string().await {
                Ok(body_string) => body_string,
                Err(_e) => {
                    self.body = Err(WebError::DataStreamReadFailed);
                    return;
                }
            };
            if !capped_string.is_complete() {
                // we have reached the provided or configured data limits while reading the data into the string.
                self.body = Err(WebError::ExceededDataLimits);
                return;
            }
            let data_string = capped_string.into_inner();
            // serde_urlencoded does not have an implementation of tokio::io::AsyncRead. as such we are serializng from a string
            match serde_urlencoded::from_str(&data_string) {
                Ok(query) => self.body = Ok(Some(query)),
                Err(_) => self.body = Err(WebError::Encoding),
            }
        }
    }
}

impl<'r> OAuthResponse<'r> {
    /// Create a new `OAuthResponse<'r>`
    pub fn new() -> Self {
        Default::default()
    }

    /// Create a new `OAuthResponse<'r>` from an existing `rocket::Response<'r>`
    pub fn from_response(response: Response<'r>) -> Self {
        OAuthResponse(response)
    }
}

impl<'r> WebRequest for OAuthRequest<'r> {
    type Error = WebError;
    type Response = OAuthResponse<'r>;

    fn query(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
        match self.query.as_ref() {
            Ok(query) => Ok(Cow::Borrowed(query as &dyn QueryParameter)),
            Err(err) => Err(*err),
        }
    }

    fn urlbody(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
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

impl<'r> WebResponse for OAuthResponse<'r> {
    type Error = WebError;

    fn ok(&mut self) -> Result<(), Self::Error> {
        self.0.set_status(Status::Ok);
        Ok(())
    }

    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> {
        self.0.set_status(Status::Found);

        // jtmorrisbytes:

        // set header's api changed from
        // self.0.set_header(header::Location(url.into()));
        // to
        let header = Header::new(header::LOCATION.as_str(), url.to_string());
        self.0.set_header(header);
        // there does not appear to be a type that implements into<Header> in rocket's library for the location header.
        // most likely because rocket expects you to return rocket::response::Redirect from handlers to perform a redirect
        Ok(())
    }

    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.0.set_status(Status::BadRequest);
        Ok(())
    }

    fn unauthorized(&mut self, kind: &str) -> Result<(), Self::Error> {
        self.0.set_status(Status::Unauthorized);
        self.0.set_raw_header("WWW-Authenticate", kind.to_owned());
        Ok(())
    }

    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> {
        self.0.set_sized_body(text.len(),Cursor::new(text.to_owned()));
        self.0.set_header(ContentType::Plain);
        Ok(())
    }

    fn body_json(&mut self, data: &str) -> Result<(), Self::Error> {
        self.0.set_sized_body(data.len(),Cursor::new(data.to_owned()));
        self.0.set_header(ContentType::JSON);
        Ok(())
    }
}
#[rocket::async_trait]
impl<'r:'static> FromRequest<'r> for OAuthRequest<'r> {
    type Error = NoError;

    async fn from_request(request: &'r Request<'_>) -> rocket::request::Outcome<Self,Self::Error> {
        Outcome::Success(Self::new(request))
    }
}

impl<'r,'o:'r> Responder<'r,'o> for OAuthResponse<'o> {
    fn respond_to(self, _: &Request) -> response::Result<'o> {
        Ok(self.0)
    }
}

impl<'r,'o:'r> Responder<'r,'o> for WebError {
    fn respond_to(self, _: &Request) -> response::Result<'o> {
        match self {
            WebError::Encoding => Err(Status::BadRequest),
            WebError::NotAForm => Err(Status::BadRequest),
            WebError::BodyNeeded => Err(Status::InternalServerError),
            WebError::DataStreamReadFailed => Err(Status::InternalServerError),
            WebError::ExceededDataLimits => Err(Status::PayloadTooLarge)
        }
    }
}

impl<'r> Default for OAuthResponse<'r> {
    fn default() -> Self {
        OAuthResponse(Default::default())
    }
}

impl<'r> From<Response<'r>> for OAuthResponse<'r> {
    fn from(r: Response<'r>) -> Self {
        OAuthResponse::from_response(r)
    }
}

impl<'r> Into<Response<'r>> for OAuthResponse<'r> {
    fn into(self) -> Response<'r> {
        self.0
    }
}
