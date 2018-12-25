//! OAuth requests encapsulated as futures.
//!
//! Some requests are dependent on data inside the request body, which is loaded asynchronously
//! by actix.  In order to provide a uniform interface, all requests are encapsulated into a
//! future yielding the specific message to be sent to the endpoint.
use std::borrow::Cow;

use code_grant::endpoint::{OAuthError, NormalizedParameter, PreGrant, QueryParameter, WebRequest, WebResponse};
use frontends::simple::request::{Body, Response, Status};

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
#[derive(Clone, Debug)]
pub struct OAuthRequest {
    query: Result<NormalizedParameter, ()>,
    auth: Result<Option<String>, ()>,
    // None if not urlencoded body or error in encoding
    body: Result<NormalizedParameter, ()>,
}

/// An http response replacement that can be sent as an actix message.
///
/// This is the generic answer to oauth authorization code and bearer token requests.
#[derive(Clone, Debug, Default)]
pub struct OAuthResponse {
    inner: ResponseKind,
}

#[derive(Clone, Debug)]
enum ResponseKind {
    ConsentForm(PreGrant),
    Inner(Response),
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

impl OAuthResponse {
    /// Construct a response that represents a consent form.
    ///
    /// Use this in an `OwnerSolicitor` implementation for `OAuthRequest` to construct the
    /// `OwnerConsent::InProgress` variant.
    pub fn consent_form(grant: PreGrant) -> Self {
        OAuthResponse {
            inner: ResponseKind::ConsentForm(grant),
        }
    }

    /// Create the response with predetermined content.
    pub fn new(inner: Response) -> Self {
        OAuthResponse {
            inner: ResponseKind::Inner(inner),
        }
    }

    /// Retrive the internal response, assuming that it does not require consent.
    pub fn unwrap(self) -> HttpResponse {
        match self.inner {
            ResponseKind::Inner(inner) => Self::convert(inner),
            ResponseKind::ConsentForm(_) => HttpResponse::InternalServerError().finish(),
        }
    }

    /// Convert the response into an http response.
    ///
    /// When the response represents a required consent form, use the argument as the response to
    /// the user agent instead. This replacement response should generally display the wanting
    /// client and required scopes in a clear and click-jacking protected manner to the
    /// authenticated resource owner. When the resource owner is not currently authenticated (i.e.
    /// logged in), this is a good opportunity to redirect to such a login page.
    pub fn get_or_consent(self, consent: HttpResponse) -> HttpResponse {
        match self.inner {
            ResponseKind::Inner(inner) => Self::convert(inner),
            ResponseKind::ConsentForm(_) => consent,
        }
    }

    /// Convert the response into an http response.
    ///
    /// When the response represents a required consent form, use the provided function to
    /// construct the response to the user agent instead. This replacement response should
    /// generally display the wanting client and required scopes in a clear and click-jacking
    /// protected manner to the authenticated resource owner. When the resource owner is not
    /// currently authenticated (i.e.  logged in), this is a good opportunity to redirect to such a
    /// login page.
    pub fn get_or_consent_with<F>(self, f: F) -> HttpResponse 
        where F: FnOnce(PreGrant) -> HttpResponse 
    {
        match self.inner {
            ResponseKind::Inner(inner) => Self::convert(inner),
            ResponseKind::ConsentForm(grant) => f(grant),
        }
    }

    fn convert(response: Response) -> HttpResponse {
        let mut builder = match response.status {
            Status::Ok => HttpResponse::Ok(),
            Status::Redirect => HttpResponse::Found(),
            Status::BadRequest => HttpResponse::BadRequest(),
            Status::Unauthorized => HttpResponse::Unauthorized(),
        };

        if let Some(url) = response.location {
            builder.header(header::LOCATION, url.into_string());
        }

        if let Some(auth) = &response.www_authenticate {
            builder.header(header::WWW_AUTHENTICATE, HeaderValue::from_str(auth).unwrap());
        }

        match response.body {
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
}

impl ResponseKind {
    fn transform(&mut self) -> &mut Response {
        match self {
            ResponseKind::Inner(ref mut inner) => inner,
            // No consent form, this response is predetermined.
            ResponseKind::ConsentForm(_) => {
                *self = ResponseKind::Inner(Response::default());
                self.transform()
            },
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

impl Default for ResponseKind {
    fn default() -> Self {
        ResponseKind::Inner(Response::default())
    }
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
        self.inner.transform().ok().map_err(|err| match err {})
    }

    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> {
        self.inner.transform().redirect(url).map_err(|err| match err {})
    }

    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.inner.transform().client_error().map_err(|err| match err {})
    }

    fn unauthorized(&mut self, kind: &str) -> Result<(), Self::Error> {
        self.inner.transform().unauthorized(kind).map_err(|err| match err {})
    }

    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> {
        self.inner.transform().body_text(text).map_err(|err| match err {})
    }

    fn body_json(&mut self, data: &str) -> Result<(), Self::Error> {
        self.inner.transform().body_json(data).map_err(|err| match err {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn is_send_sync() {
        trait Test: Send + Sync + 'static { }
        impl Test for OAuthRequest { }
        impl Test for OAuthResponse { }
    }
}
