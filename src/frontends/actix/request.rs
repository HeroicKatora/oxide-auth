//! OAuth requests encapsulated as futures.
//!
//! Some requests are dependent on data inside the request body, which is loaded asynchronously
//! by actix.  In order to provide a uniform interface, all requests are encapsulated into a
//! future yielding the specific message to be sent to the endpoint.
use std::collections::HashMap;

use code_grant::frontend::OAuthError;

use super::actix_web::{HttpMessage, HttpRequest};
use super::actix_web::dev::UrlEncoded;
use super::futures::{Async, Future, Poll};

use super::resolve::ResolvedRequest;
use super::message;

/// The item requests an authorization code, provided by the endpoint with the owners approval.
pub struct AuthorizationCode {
    request: HttpRequest,
    owner: Option<message::BoxedOwner>,
}

/// Yields a message that requests a bearer token from the endpoint.
pub struct AccessToken {
    request: HttpRequest,
    body: UrlEncoded<HttpRequest, HashMap<String, String>>,
}

/// Produces a message that checks the access rights of the http requests bearer token.
pub struct Guard {
    request: HttpRequest,
}

impl AuthorizationCode {
    pub(super) fn new(request: HttpRequest, owner: message::BoxedOwner) -> Self {
        AuthorizationCode {
            request,
            owner: Some(owner),
        }
    }
}

impl AccessToken {
    pub(super) fn new(request: HttpRequest) -> Self {
        AccessToken {
            request: request.clone(),
            body: request.urlencoded(),
        }
    }
}

impl Guard {
    pub(super) fn new(request: HttpRequest) -> Self {
        Guard {
            request,
        }
    }
}

impl Future for AuthorizationCode {
    type Item = message::AuthorizationCode;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        Ok(Async::Ready(message::AuthorizationCode {
            request: ResolvedRequest::headers_only(self.request.clone()),
            owner: self.owner.take().unwrap(),
        }))
    }
}

impl Future for AccessToken {
    type Item = message::AccessToken;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.body.poll() {
            Ok(Async::Ready(body)) => Ok(Async::Ready(message::AccessToken(
                ResolvedRequest::with_body(self.request.clone(), body)))),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(_err) => Err(OAuthError::InvalidRequest),
        }
    }
}

impl Future for Guard {
    type Item = message::Guard;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        Ok(Async::Ready(message::Guard(
            ResolvedRequest::headers_only(self.request.clone())
        )))
    }
}
