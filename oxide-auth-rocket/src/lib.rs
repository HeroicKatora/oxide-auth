//! Adaptions and integration for rocket.
#![warn(missing_docs)]

mod failure;

use std::convert::TryInto;
use rocket::http::Header;
use std::marker::PhantomData;

use rocket::data::{self,DataStream, FromData, Limits};
use rocket::{Data, Request, Response};
use rocket::http::{ContentType, Status};
use rocket::request::FromRequest;
use rocket::response::{self, Responder};
use rocket::outcome::Outcome;

use oxide_auth::endpoint::{NormalizedParameter, WebRequest, WebResponse};
use oxide_auth::frontends::dev::*;

pub use oxide_auth::frontends::simple::endpoint::Generic;
pub use oxide_auth::frontends::simple::request::NoError;
pub use self::failure::OAuthFailure;



/* 
    A note from a contributer: jtmorrisbytes.
    When rocket transitioned from 0.4 to 0.5, they went to async code.
    The OAuthRequest type is expected to uphold the 'static lifetime bound in FromRequest
    because its difficult to hold data across an await point. I was unable to make the code work
    unless ONLY OAuthRequest was bound by the 'static lifetime.
    
    I also changed the way OAuthRequest Works.
    I Implemented FromData, which allows you to use the OAuthRequest type as a data guard, and
    that the body data will be automatically parsed. see the examples.
    
    add_body now takes a DataStream instead of a Data.
    Rocket now enforces data limits upon data guards.

    The limits are configured using rocket's built in 'form' limit configuration. if no limit is specified, the 
    library will use the default. a seperate limit can be added if required by feedback from the library users.

    I did not feel like keeping the OAuthRequest Type a simple wrapper around request due to managing lifetimes and decided
    to make it it's own type that holds only the data it needs. If we need to keep the original type,
    we may be able to make it work since you can tell the compiler to make the request outlive the response.
*/ 
/// Header value for WWW_AUTHENTICATE. this is not present in the version of hyper that rocket depends on
const WWW_AUTHENTICATE: &str = "www_authenticate";

/// allows this type to be used as a data guard. replaces OAuthRequest::add_body.
/// if you dont need the request body, then simply use FromRequest
/// limits are configured in rocket.toml using the "form" limit. if no limit is set, this implementation uses the default defined by rocket::limit::Limits::FORM
/// 
/// ex: Data Guard
/// // the format argument ensures that this handler will not be called unless the content-typ matches the 'format' argument in the macor
/// #[rocket::get("/example"),data="<oauth_request>",format="application/x-www-urlencoded"]
/// fn handler(oauth_request: OAuthRequest) -> () {
///     // the oauth_request variable has the body set here due to the FromData implementation. calling add_body is not needed 
/// }
/// ex FromRequest
/// #[rocket::get("/example")]
/// fn handler(oauth_request: OAuthRequest) -> {
// /     the oauth_request variable DOES NOT have the body set here because rocket uses FromRequest here
/// }
// Note: the 'impl<'r> FromData<'r> for OAuthRequest<'static> is intentional. only OAuthRequest is required here to make this work
// if you try to bind 'r: 'static then the code wont compile due to 'borrowed data __req escapes from the function' 
#[rocket::async_trait]
impl<'r> FromData<'r> for OAuthRequest<'static> {
    type Error=NoError;
    async fn from_data(request: &'r Request<'_>, data: Data<'r>) -> data::Outcome<'r,Self,Self::Error> {
        let mut _self = Self::new(request);
        // check the content type here
        match request.content_type() {
            Some(content_type) if content_type.is_form()  => {},
            _=>{
                _self.body = Err(WebError::NotAForm);
                return data::Outcome::Success(Self::new(request))
            }
        };
        let limit = request.limits().get("form").unwrap_or(Limits::FORM);
        let data_stream = data.open(limit);
        _self.add_body(data_stream).await;

        data::Outcome::Success(_self)

    }
} 




/// Request guard that also buffers OAuth data internally.
pub struct OAuthRequest<'r> {
    auth: Option<String>,
    query: Result<NormalizedParameter, WebError>,
    body: Result<Option<NormalizedParameter>, WebError>,
    lifetime: PhantomData<&'r ()>,
}

/// Response type for Rocket OAuth requests
///
/// A type that holds all of the response data
#[derive(Debug,Clone)]
pub struct OAuthResponse {
    /// represents the body of the request
    body:String,
    /// Represents the status of the request. Default is Status::OK
    status: rocket::http::Status,
    content_type: ContentType,
    /// Optional. represents a location header value. if Some(_) a location header will be set.
    /// otherwise no location header will be set
    header_location: Option<String>,
    /// represents a www_authenticate header value
    header_www_authenticate: Option<String>,
    body_length: usize
}
impl<'r> OAuthResponse {
    /// attempts to convert this type into an instance of rocket::response::Response. if it fails, it returns a status code
    pub fn try_into_response(self) -> response::Result<'r> {
        let mut builder = Response::build();
        let mut response = &mut builder;
        response = response.status(self.status);
        // set the content type
        let content_type = Header::new(rocket::http::hyper::header::CONTENT_TYPE.to_string(), self.content_type.to_string());
        // set the location header if present
        if let Some(location) = self.header_location {
            response = response.header(Header::new(rocket::http::hyper::header::LOCATION.to_string(), location));
        }
        if let Some(www_authenticate) = self.header_www_authenticate {
            response = response.header(Header::new(WWW_AUTHENTICATE, www_authenticate));
        }
        response = response.header(content_type);
        Ok(response.sized_body(self.body_length, std::io::Cursor::new(self.body)).finalize())
    }
    /// sets the content type for this response
    pub fn set_content_type(&mut self,content_type:ContentType) -> &mut Self {
        self.content_type = content_type;
        self
    }
    /// sets or unsets the location header for this response. 
    pub fn set_location(&mut self,location: Option<&str>) -> &mut Self {
        self.header_location = location.map(|str| str.to_string());
        self
    }
    /// sets the status for this request. Default is Status::OK
    pub fn set_status(&mut self,status: Status) -> &mut Self {
        self.status = status;
        self
    }

    /// sets the content type and body to be a html document
    pub fn body_html(&mut self, html: &str) -> &mut Self {
        self.content_type = ContentType::HTML;
        self.body = html.to_string();
        self.body_length = self.body.len();
        self
    }
    /// sets the content type and body to be a text document
    pub fn body_text(&mut self, text: &str) -> &mut Self {
        self.content_type = ContentType::Text;
        self.body = text.to_string();
        self.body_length = self.body.len();
        self
    }
    /// sets the content_type and body to be a json document
    pub fn body_json(&mut self,json: &str) -> &mut Self {
        self.content_type = ContentType::JSON;
        self.body = json.to_string();
        self.body_length= self.body.len();
        self
    }
}
impl std::default::Default for OAuthResponse {
    fn default() -> Self {
        Self { status: rocket::http::Status::Ok,content_type: ContentType::Text,header_location:None,header_www_authenticate:None,body:String::new(),body_length:0 }
    }
}

impl <'r,'o: 'r> Responder<'r,'o> for OAuthResponse {
    fn respond_to(self, _request: &'r Request<'_>) -> response::Result<'o> {
        // build a new response
        let mut builder = Response::build();
        let mut response = &mut builder;
        response = response.status(self.status);
        // set the content type
        let content_type = Header::new(rocket::http::hyper::header::CONTENT_TYPE.to_string(), self.content_type.to_string());
        // set the location header if present
        if let Some(location) = self.header_location {
            response = response.header(Header::new(rocket::http::hyper::header::LOCATION.to_string(), location));
        }
        if let Some(www_authenticate) = self.header_www_authenticate {
            response = response.header(Header::new(WWW_AUTHENTICATE, www_authenticate));
        }
        response = response.header(content_type);
        Ok(response.sized_body(self.body_length, std::io::Cursor::new(self.body)).finalize())
    }
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

    /// Failed to read the datastream into a string while attemting to call add_body
    DataStreamReadFailed,

    /// reached the default or  configured maximum data size limits while reading the datastream into a string and there is still data remaining
    ExceededDataLimits 

}
impl std::fmt::Display for WebError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::Encoding => {
                write!(f,"A parameter was encoded incorrectly while parsing a form")
            },
            Self::BodyNeeded => {
                write!(f,"The body was needed but was not provided")
            }
            Self::NotAForm => {
                write!(f,"Form data was requested but the request was not a form")
            }
            Self::DataStreamReadFailed => {
                write!(f,"An I/O error occurred while attempting to read the data stream into a buffer")
            }
            Self::ExceededDataLimits => {
                write!(f,"Exceeded the data limits while attempting to read the data stream into a buffer")
            }
        }
    }
}




impl<'r> OAuthRequest<'r> {
    /// Create the request data from request headers.
    ///
    /// Some oauth methods need additionally the body data which you can attach later.
    pub fn new<'a>(request: &'a Request<'_>) -> Self {
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
    ///
    pub async fn add_body(&mut self, data_stream: DataStream<'_>) {
        // // Nothing to do if we already have a body, or already generated an error. This includes
        // // the case where the content type does not indicate a form, as the error is silent until a
        // // body is explicitely requested.

        // // jtmorrisbytes:
        // // not sure whether this is the desired behavior, but
        // // trying to prevent defining our own default here
        // // https://api.rocket.rs/v0.5/rocket/data/struct.Limits
        // // unsure whether to use FORM or DATA_FORM here. More research is required
        // // in order to get the configured limits from request.rocket().limits(),
        // // we need a reference to the request here.
        
        
        if let Ok(None) = self.body {
        //     // accepts the limit given to the function or uses the rocket configured default
        //     let limit = limits.unwrap_or(rocket::data::Limits::FORM);
        //     let data = data.open(limit);
        //     // jtmorrisbytes:
        //     // datastream has several options
        //     // 
        //     // we can stream the data into a file and read it from there
        //     // we can convert the datastream into a vector of bytes.
        //     // we can stream the stream into another vector of bytes
        //     // we can also convert the datastream into a string.
        //     // if we convert the datastream into a string, it will guarentee that the data is valid UTF-8
        //     // 
        //     // https://api.rocket.rs/v0.5/rocket/data/struct.DataStream
        //     // but std::io::read is no longer implemented
        //     // in favor of tokio::io::util::AsyncRead
        //     // 
        //     // I am going to read the data into a string, then serialize the data

        //     // try to read the data into a string. if it fails, set an error and retern early
            let data_string = match data_stream.into_string().await {
                Ok(capped_string) => capped_string,
                Err(_e) => {
                    self.body = Err(WebError::DataStreamReadFailed);
                    return;
                }
            };
            if !data_string.is_complete() {
        //         // we have reached the provided or configured data limits while reading the data into the string.
                self.body = Err(WebError::ExceededDataLimits);
                return;
            }
        //  serde_urlencoded does not have an implementation of tokio::io::AsyncRead. as such we are serializng from a string
        match serde_urlencoded::from_str(&data_string) {
                Ok(query) => self.body = Ok(Some(query)),
                Err(_) => self.body = Err(WebError::Encoding),
            }
        }
    }
}

impl OAuthResponse {
    /// Create a new `OAuthResponse<'r>`
    pub fn new() -> Self {
        Default::default()
    }

    // Create a new `OAuthResponse<'r>` from an existing `rocket::Response<'r>`
    
    // pub fn from_response<'r>(response: Response<'r>) -> Self {
    //     // response.resp
    //     Self {response.status}
    // }

    // pub fn into_response(self,response: Response)
}

impl<'r> WebRequest for OAuthRequest<'r> {
    type Error = WebError;
    type Response = OAuthResponse;

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

impl WebResponse for OAuthResponse {
    type Error = WebError;

    fn ok(&mut self) -> Result<(), Self::Error> {
        self.status = Status::Ok;
        // self.0.set_status(Status::Ok);
        Ok(())
    }

    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> {
        self.status = Status::Found;
        // jtmorrisbytes:

        // set header's api changed from
        // self.0.set_header(header::Location(url.into()));
        // to
        // let header = Header::new(header::LOCATION.as_str(), url.to_string());
        self.header_location = Some(url.to_string());
        // there does not appear to be a type that implements into<Header> in rocket's library for the location header.
        // most likely because rocket expects you to return rocket::response::Redirect from handlers to perform a redirect
        Ok(())
    }

    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.status = Status::BadRequest;
        Ok(())
    }

    fn unauthorized(&mut self, kind: &str) -> Result<(), Self::Error> {
        self.status = Status::Unauthorized;
        self.header_www_authenticate = Some(kind.to_owned());
        Ok(())
    }

    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> {
        self.body_text(text);
        Ok(())
    }

    fn body_json(&mut self, data: &str) -> Result<(), Self::Error> {
        self.body_json(data);
        Ok(())
    }
}
#[rocket::async_trait]
impl<'r> FromRequest<'r> for OAuthRequest<'static> {
    type Error = NoError;

    async fn from_request(request: &'r Request<'_>) -> rocket::request::Outcome<Self,Self::Error> {
        Outcome::Success(Self::new(request))
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

// impl<'r> Default for OAuthResponse<'r> {
//     fn default() -> Self {
//         OAuthResponse(Default::default())
//     }
// }

// impl<'r> From<Response<'r>> for OAuthResponse<'r> {
//     fn from(r: Response<'r>) -> Self {
//         OAuthResponse::from_response(r)
//     }
// }

impl<'r> TryInto<Response<'r>> for OAuthResponse {
    type Error = rocket::http::Status;
    fn try_into(self) -> Result<Response<'r>, Self::Error> {
        self.try_into_response()   
    }
}
