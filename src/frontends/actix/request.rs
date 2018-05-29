use std::collections::HashMap;

use code_grant::frontend::OAuthError;

use super::actix_web::{HttpMessage, HttpRequest};
use super::actix_web::dev::UrlEncoded;
use super::futures::{Async, Future, Poll};

use super::resolve::ResolvedRequest;
use super::message;

pub struct AuthorizationCode {
    request: HttpRequest,
    owner: Option<message::BoxedOwner>,
}

pub struct AccessToken {
    request: HttpRequest,
    body: UrlEncoded<HttpRequest, HashMap<String, String>>,
}

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
            Err(_err) => Err(OAuthError::AccessDenied),
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
