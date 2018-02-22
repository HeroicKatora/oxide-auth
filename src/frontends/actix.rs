extern crate actix_web;
extern crate futures;

use code_grant::frontend::{WebRequest, WebResponse};
pub use code_grant::frontend::{AccessFlow, AuthorizationFlow, GrantFlow};
use code_grant::frontend::{Authentication, OAuthError, OwnerAuthorizer};
use code_grant::prelude::*;

use std::borrow::Cow;
use std::collections::HashMap;

use self::actix_web::{HttpRequest, HttpResponse, StatusCode};
use self::actix_web::dev::UrlEncoded;
use self::futures::{Async, Future, Poll};
use url::Url;

pub trait OAuth {
    fn oauth2(self) -> OAuthRequest;
}

pub struct OAuthRequest(HttpRequest);

struct ResolvedRequest<'a> {
    request: &'a HttpRequest,
    authentication: Result<Option<Cow<'a, str>>, ()>,
    query: Result<HashMap<String, Vec<String>>, ()>,
    body: Result<HashMap<String, Vec<String>>, ()>,
}

enum OAuthRequestError {
    UrlEncoded(<UrlEncoded as Future>::Error),
}

impl OAuth for HttpRequest {
    fn oauth2(self) -> OAuthRequest {
        OAuthRequest(self)
    }
}

impl OAuthRequest {
    fn authorization_code<'f, F: 'f, A: 'f>(self, f: F, auth: A) -> AuthorizationCodeRequest<'f, F, A>
    where
        F: FnOnce() -> AuthorizationFlow<'f>,
        A: Fn(&HttpRequest, &PreGrant) -> Result<(Authentication, HttpResponse), OAuthError> {
        let OAuthRequest(request) = self;

        AuthorizationCodeRequest {
            request: request,
            owner_authorization: Some(auth),
            context: Some(f),
        }
    }

    fn access_token<'f, F: 'f>(self, f: F) -> GrantRequest<'f, F>
    where
        F: FnOnce() -> GrantFlow<'f> {
        let OAuthRequest(request) = self;
        let body = request.urlencoded();

        GrantRequest {
            request: request,
            body: body,
            context: Some(f),
        }
    }

    fn guard<'f, F: 'f>(self, f: F) -> GuardRequest<'f, F>
    where
        F: FnOnce() -> AccessFlow<'f> {
        let OAuthRequest(request) = self;

        GuardRequest {
            request: request,
            context: Some(f),
        }
    }
}

struct AuthorizationCodeRequest<'f, F: 'f, A: 'f>
where
    F: FnOnce() -> AuthorizationFlow<'f>,
    A: Fn(&HttpRequest, &PreGrant) -> Result<(Authentication, HttpResponse), OAuthError> {
    request: HttpRequest,
    owner_authorization: Option<A>,
    context: Option<F>,
}

struct GrantRequest<'f, F: 'f>
where
    F: FnOnce() -> GrantFlow<'f> {
    request: HttpRequest,
    body: UrlEncoded,
    context: Option<F>,
}

struct GuardRequest<'f, F: 'f>
where
    F: FnOnce() -> AccessFlow<'f> {
    request: HttpRequest,
    context: Option<F>,
}

impl<'a> WebRequest for ResolvedRequest<'a> {
    type Error = OAuthError;
    type Response = HttpResponse;

     fn query(&mut self) -> Result<Cow<HashMap<String, Vec<String>>>, ()> {
         self.query.as_ref().map(Cow::Borrowed).map_err(|_| ())
     }

     fn urlbody(&mut self) -> Result<Cow<HashMap<String, Vec<String>>>, ()> {
         self.body.as_ref().map(Cow::Borrowed).map_err(|_| ())
     }

     fn authheader(&mut self) -> Result<Option<Cow<str>>, ()>{
         self.authentication.clone()
     }
}

impl WebResponse for HttpResponse {
    type Error = OAuthError;

    fn redirect(url: Url) -> Result<Self, Self::Error> {
        HttpResponse::Found()
            .header("Location", url.as_str())
            .finish()
            .map_err(|_| OAuthError::InternalCodeError())
    }

    fn text(text: &str) -> Result<Self, Self::Error> {
        HttpResponse::Ok()
            .content_type("text/plain")
            .body(text.to_owned())
            .map_err(|_| OAuthError::InternalCodeError())
    }

    fn json(data: &str) -> Result<Self, Self::Error> {
        HttpResponse::Ok()
            .content_type("application/json")
            .body(data.to_owned())
            .map_err(|_| OAuthError::InternalCodeError())
    }

    fn as_client_error(mut self) -> Result<Self, Self::Error> {
        self.status_mut().clone_from(&StatusCode::BAD_REQUEST);
        Ok(self)
    }

    fn as_unauthorized(mut self) -> Result<Self, Self::Error> {
        self.status_mut().clone_from(&StatusCode::UNAUTHORIZED);
        Ok(self)
    }

    fn with_authorization(mut self, kind: &str) -> Result<Self, Self::Error> {
        self.status_mut().clone_from(&StatusCode::UNAUTHORIZED);
        let header_content = kind.parse().map_err(|_| OAuthError::InternalCodeError())?;
        self.headers_mut().insert("WWW-Authenticate", header_content);
        Ok(self)
    }
}

impl<'a> ResolvedRequest<'a> {
    fn headers_only(request: &'a mut HttpRequest) -> Self {
        ResolvedRequest {
            request: request,
            authentication: match request.headers().get("Authentication").map(|header| header.to_str()) {
                None => Ok(None),
                Some(Ok(as_str)) => Ok(Some(Cow::Borrowed(as_str))),
                Some(Err(_)) => Err(())
            },
            query: Ok(request
                .query()
                .iter()
                .map(|&(ref key, ref val)| (key.clone().into_owned(), vec![val.clone().into_owned()]))
                .collect()),
            body: Err(()),
        }
    }

    fn with_body(request: &'a mut HttpRequest, body: HashMap<String, String>) -> Self {
        let mut resolved = Self::headers_only(request);
        resolved.body = Ok(body
            .into_iter()
            .map(|(key, val)| (key, vec![val]))
            .collect());
        resolved
    }
}

struct ResolvedOwnerAuthorization<A>(A);

impl<'f, A: 'f> OwnerAuthorizer<ResolvedRequest<'f>> for ResolvedOwnerAuthorization<A>
where A: Fn(&HttpRequest, &PreGrant) -> Result<(Authentication, HttpResponse), OAuthError> {
    fn get_owner_authorization(&self, request: &mut ResolvedRequest<'f>, grant: &PreGrant)
    -> Result<(Authentication, HttpResponse), OAuthError> {
        self.0(request.request, grant)
    }
}

impl<'f, F: 'f, A: 'f> Future for AuthorizationCodeRequest<'f, F, A>
where
    F: FnOnce() -> AuthorizationFlow<'f>,
    A: Fn(&HttpRequest, &PreGrant) -> Result<(Authentication, HttpResponse), OAuthError> {
    type Item = HttpResponse;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let resolved = ResolvedRequest::headers_only(&mut self.request);

        // Contract error if this happens multiple times
        let context = self.context.take().unwrap()();

        let owner_authorization = self.owner_authorization.take().unwrap();
        let owner_authorization = ResolvedOwnerAuthorization(owner_authorization);

        match context.handle(resolved, &owner_authorization) {
            Ok(response) => Ok(Async::Ready(response)),
            Err(err) => Err(err),
        }
    }
}


impl<'f, F: 'f> Future for GrantRequest<'f, F>
where
    F: FnOnce() -> GrantFlow<'f> {
    type Item = HttpResponse;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.body.poll() {
            Ok(Async::Ready(body)) => {
                let resolved = ResolvedRequest::with_body(&mut self.request, body);
                // Contract error if this happens multiple times
                let context = self.context.take().unwrap()();
                match context.handle(resolved) {
                    Ok(response) => Ok(Async::Ready(response)),
                    Err(err) => Err(err),
                }
            },
            Ok(Async::NotReady) => Ok(Async::NotReady),

            // Not a valid url encoded body
            Err(err) => Err(OAuthError::AccessDenied),
        }
    }
}

impl<'f, F: 'f> Future for GuardRequest<'f, F>
where
    F: FnOnce() -> AccessFlow<'f> {
    type Item = ();
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let resolved = ResolvedRequest::headers_only(&mut self.request);

        // Contract error if this happens multiple times
        let context = self.context.take().unwrap()();
        match context.handle(resolved) {
            Ok(response) => Ok(Async::Ready(response)),
            Err(err) => Err(err),
        }
    }
}
