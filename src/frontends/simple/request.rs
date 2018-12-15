//! Simple, owning request and response types.
use code_grant::endpoint::{QueryParameter, WebRequest, WebResponse};

use std::borrow::Cow;
use std::collections::HashMap;

use url::Url;

/// Open and simple implementation of `WebRequest`.
#[derive(Clone, Debug, Default)]
pub struct Request {
    /// The key-value pairs in the url query component.
    pub query: HashMap<String, String>,

    /// The key-value pairs of a `x-www-form-urlencoded` body.
    pub urlbody: HashMap<String, String>,

    /// Provided authorization header.
    pub auth: Option<String>,
}

/// Open and simple implementation of `WebResponse`.
#[derive(Clone, Debug, Default)]
pub struct Response {
    /// HTTP status code.
    pub status: Status,

    /// A location header, for example for redirects.
    pub location: Option<Url>,

    /// Indicates how the client should have authenticated.
    ///
    /// Only set with `Unauthorized` status.
    pub www_authenticate: Option<String>,

    /// Encoded body of the response.
    ///
    /// One variant for each possible encoding type.
    pub body: Option<Body>,
}

/// An enum containing the necessary HTTP status codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Status {
    /// Http status code 200.
    Ok,

    /// Http status code 302.
    Redirect,

    /// Http status code 400.
    BadRequest,

    /// Http status code 401.
    Unauthorized,
}

/// Models the necessary body contents.
/// 
/// Real HTTP protocols should set a content type header for each of the body variants.
#[derive(Clone, Debug)]
pub enum Body {
    /// A pure text body.
    Text(String),

    /// A json encoded body, `application/json`.
    Json(String),
}

/// An uninhabited error type for simple requests and responses.
///
/// Since these types are built to never error on their operation, and `!` is not the stable unique
/// representation for uninhabited types, this simple enum without variants is used instead.
pub enum NoError { }

impl WebRequest for Request {
    type Error = NoError;
    type Response = Response;

    fn query(&mut self) -> Result<Cow<QueryParameter + 'static>, Self::Error> {
        Ok(Cow::Borrowed(&self.query))
    }

    fn urlbody(&mut self) -> Result<Cow<QueryParameter + 'static>, Self::Error> {
        Ok(Cow::Borrowed(&self.urlbody))
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, Self::Error> {
        Ok(self.auth.as_ref().map(|string| Cow::Borrowed(string.as_str())))
    }
}

impl WebResponse for Response {
    type Error = NoError;

    fn ok(&mut self) -> Result<(), Self::Error> {
        self.status = Status::Ok;
        self.location = None;
        self.www_authenticate = None;
        Ok(())
    }

    /// A response which will redirect the user-agent to which the response is issued.
    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> {
        self.status = Status::Redirect;
        self.location = Some(url);
        self.www_authenticate = None;
        Ok(())
    }

    /// Set the response status to 400.
    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.status = Status::BadRequest;
        self.location = None;
        self.www_authenticate = None;
        Ok(())
    }

    /// Set the response status to 401 and add a `WWW-Authenticate` header.
    fn unauthorized(&mut self, header_value: &str) -> Result<(), Self::Error> {
        self.status = Status::Unauthorized;
        self.location = None;
        self.www_authenticate = Some(header_value.to_owned());
        Ok(())
    }

    /// A pure text response with no special media type set.
    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> {
        self.body = Some(Body::Text(text.to_owned()));
        Ok(())
    }

    /// Json repsonse data, with media type `aplication/json.
    fn body_json(&mut self, data: &str) -> Result<(), Self::Error> {
        self.body = Some(Body::Json(data.to_owned()));
        Ok(())
    }
}

impl NoError {
    /// Turn this into any type.
    ///
    /// Since `NoError` is uninhabited, this always works but is never executed.
    pub fn into<T>(self) -> T {
        match self { }
    }
}

impl Default for Status {
    fn default() -> Self {
        Status::Ok
    }
}
