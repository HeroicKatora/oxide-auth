//! OAuth requests encapsulated as futures.
//!
//! Some requests are dependent on data inside the request body, which is loaded asynchronously
//! by actix.  In order to provide a uniform interface, all requests are encapsulated into a
//! future yielding the specific message to be sent to the endpoint.
use std::borrow::Cow;

use code_grant::endpoint::{OAuthError, NormalizedParameter, QueryParameter, WebRequest, WebResponse};
use frontends::simple::request::{Body, Response, Status};

use super::message::{AuthorizationCode, AccessToken, BoxedOwner, Resource};

use super::actix_web::{HttpMessage, HttpRequest, HttpResponse};
use super::actix_web::dev::UrlEncoded;
use super::actix_web::http::header::{self, HeaderValue};
use super::futures::{Async, Future, Poll};

use url::Url;
use super::serde_urlencoded;

/// A future for all OAuth related data.
pub struct OAuthFuture {
    inner: HttpRequest,
    body: Option<UrlEncoded<HttpRequest, Vec<(String, String)>>>,
}

/// Sendable struct implementing `WebRequest`.
pub struct OAuthRequest {
    query: Result<NormalizedParameter, ()>,
    auth: Result<Option<String>, ()>,
    // None if not urlencoded body or error in encoding
    body: Result<NormalizedParameter, ()>,
}

/// An http response replacement that can be sent as an actix message.
///
/// This is the generic answer to oauth authorization code and bearer token requests.
pub struct OAuthResponse {
    inner: Response,
}

impl OAuthFuture {
    /// Extract relevant components from a request.
    ///
    /// The result of the future is `Send + Sync` so that it can be used in messages.
    pub fn new<S>(request: &HttpRequest<S>) -> Self {
        let request = request.drop_state();
        let body = if let Some(ctype) = request.request().headers().get(header::CONTENT_TYPE) {
            if ctype == "application/x-www-form-urlencoded" {
                Some(UrlEncoded::new(&request))
            } else {
                None
            }
        } else {
            None
        };

        OAuthFuture {
            inner: request,
            body,
        }
    }
}

impl Future for OAuthFuture {
    type Item = OAuthRequest;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let body = match self.body.as_mut().map(Future::poll) {
            Some(Ok(Async::NotReady)) => return Ok(Async::NotReady),
            Some(Ok(Async::Ready(body))) => Ok(body.into_iter().collect()),
            Some(Err(_)) => Err(()),
            None => Err(()),
        };

        // We can not trust actix not deduplicating keys.
        let query = match self.inner.uri().query().map(serde_urlencoded::from_str::<Vec<(String, String)>>) {
            None => Ok(NormalizedParameter::default()),
            Some(Ok(query)) => Ok(query.into_iter().collect()),
            Some(Err(_)) => Err(()),
        };

        let auth = self.inner.headers()
            .get(header::AUTHORIZATION)
            .map(|header| header.to_str().map(str::to_string));

        let auth = match auth {
            Some(Ok(auth)) => Ok(Some(auth)),
            Some(Err(_)) => Err(()),
            None => Ok(None),
        };

        Ok(Async::Ready(OAuthRequest {
            query,
            auth,
            body,
        }))
    }
}

impl OAuthRequest {
    /*
    /// Build an authorization code request from the http request.
    ///
    /// The provided method `check` will be sent inside the request and MUST validate that the
    /// resource owner has approved the authorization grant that was requested.  This is
    /// application specific logic that MUST check that the validiting owner is authenticated.
    pub fn authorization_code<F>(self, check: F) -> AuthorizationCode
    {
        AuthorizationCode::new(self, check.into())
    }

    /// Treat http request as a bearer token request.
    pub fn access_token(self) -> AccessToken {
        AccessToken::new(self)
    }

    /// Extract the bearer token from the request to guard a resource.
    pub fn resource(self) -> Resource {
        Resource::new(self)
    }
    */
}

impl WebRequest for OAuthRequest {
    type Error = OAuthError;
    type Response = OAuthResponse;

     fn query(&mut self) -> Result<Cow<QueryParameter + 'static>, Self::Error> {
         self.query.as_ref()
             .map(|query| Cow::Borrowed(query as &QueryParameter))
             .map_err(|_| OAuthError::InvalidRequest)
     }

     fn urlbody(&mut self) -> Result<Cow<QueryParameter + 'static>, Self::Error> {
         self.body.as_ref()
             .map(|body| Cow::Borrowed(body as &QueryParameter))
             .map_err(|_| OAuthError::InvalidRequest)
     }

     fn authheader(&mut self) -> Result<Option<Cow<str>>, Self::Error>{
         match &self.auth {
             &Ok(Some(ref string)) => Ok(Some(Cow::Borrowed(string))),
             &Ok(None) => Ok(None),
             &Err(_) => Err(OAuthError::InvalidRequest)
         }
     }
}

impl WebResponse for OAuthResponse {
    type Error = OAuthError;

    fn ok(&mut self) -> Result<(), Self::Error> {
        self.inner.ok().map_err(|err| match err {})
    }

    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> {
        self.inner.redirect(url).map_err(|err| match err {})
    }

    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.inner.client_error().map_err(|err| match err {})
    }

    fn unauthorized(&mut self, kind: &str) -> Result<(), Self::Error> {
        self.inner.unauthorized(kind).map_err(|err| match err {})
    }

    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> {
        self.inner.body_text(text).map_err(|err| match err {})
    }

    fn body_json(&mut self, data: &str) -> Result<(), Self::Error> {
        self.inner.body_json(data).map_err(|err| match err {})
    }
}

impl OAuthResponse {
    fn convert(self) -> HttpResponse {
        let mut builder = match self.inner.status {
            Status::Ok => HttpResponse::Ok(),
            Status::Redirect => HttpResponse::Found(),
            Status::BadRequest => HttpResponse::BadRequest(),
            Status::Unauthorized => HttpResponse::Unauthorized(),
        };

        if let Some(url) = self.inner.location {
            builder.header(header::LOCATION, url.into_string());
        }

        if let Some(auth) = &self.inner.www_authenticate {
            builder.header(header::WWW_AUTHENTICATE, HeaderValue::from_str(auth).unwrap());
        }

        match self.inner.body {
            Some(Body::Text(text)) => {
                builder.content_type("text/plain");
                builder.body(text);
            },
            Some(Body::Json(text)) => {
                builder.content_type("application/json");
                builder.body(text);
            },
            None => (),
        }

        builder.finish()
    }

    /// Convert the response into an http response.
    pub fn actix_response(self) -> HttpResponse {
        OAuthResponse::convert(self)
    }
}

impl From<OAuthResponse> for HttpResponse {
    fn from(resolved: OAuthResponse) -> Self {
        resolved.actix_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_send_sync() {
        trait Test: Send + Sync + 'static { }
        impl Test for OAuthRequest { }
        impl Test for OAuthResponse { }
    }
}
