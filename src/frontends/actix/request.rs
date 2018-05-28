use std::collections::HashMap;

use super::actix_web::HttpRequest;
use super::actix_web::dev::UrlEncoded;
use super::futures::{Async, Future, Poll};

use super::resolve::ResolvedRequest;
use super::message;

pub struct AuthorizationCode {
    pub(super) request: Option<HttpRequest>,
}

pub struct AccessToken {
    pub(super) request: Option<HttpRequest>,
    pub(super) body: UrlEncoded<HttpRequest, HashMap<String, String>>,
}

pub struct Guard {
    pub(super) request: Option<HttpRequest>,
}

/*
impl Future for AuthorizationCode {
    type Item = message::AuthorizationCode;
    type Error = OAuthError;
}

impl Future for AccessToken {
    type Item = message::AccessToken;
    type Error = OAuthError;
}

impl Future for Guard {
    type Item = message::Guard;
    type Error = OAuthError;
}*/
