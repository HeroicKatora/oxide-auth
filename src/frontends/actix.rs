extern crate actix_web;
extern crate futures;

use code_grant::frontend::{WebRequest, WebResponse};
pub use code_grant::frontend::{AccessFlow, AuthorizationFlow, GrantFlow};
pub use code_grant::frontend::{Authentication, OAuthError, OwnerAuthorizer};
pub use code_grant::prelude::*;

use std::borrow::Cow;
use std::collections::HashMap;

use self::actix_web::{HttpRequest, HttpResponse, StatusCode};
use self::actix_web::dev::UrlEncoded;
use self::futures::{Async, Poll};
pub use self::futures::Future;
use url::Url;

pub trait OAuth {
    type State;
    fn oauth2(self) -> OAuthRequest<Self::State>;
}

pub struct OAuthRequest<State>(HttpRequest<State>);

struct ResolvedRequest<State> {
    request: HttpRequest<State>,
    authorization: Result<Option<String>, ()>,
    query: Result<HashMap<String, Vec<String>>, ()>,
    body: Result<HashMap<String, Vec<String>>, ()>,
}

impl<State> OAuth for HttpRequest<State> {
    type State = State;
    fn oauth2(self) -> OAuthRequest<State> {
        OAuthRequest(self)
    }
}

impl<State> OAuthRequest<State> {
    pub fn authorization_code(self) -> AuthorizationCodeRequest<State> {
        let OAuthRequest(request) = self;

        AuthorizationCodeRequest {
            request: Some(request),
        }
    }

    pub fn access_token(self) -> GrantRequest<State> {
        let OAuthRequest(request) = self;
        let body = request.urlencoded();

        GrantRequest {
            request: Some(request),
            body: body,
        }
    }

    pub fn guard(self) -> GuardRequest<State> {
        let OAuthRequest(request) = self;

        GuardRequest {
            request: Some(request),
        }
    }
}

pub struct AuthorizationCodeRequest<State> {
    request: Option<HttpRequest<State>>,
}

pub struct GrantRequest<State> {
    request: Option<HttpRequest<State>>,
    body: UrlEncoded,
}

pub struct GuardRequest<State> {
    request: Option<HttpRequest<State>>,
}

pub struct ReadyAuthorizationCodeRequest<State>(ResolvedRequest<State>);
pub struct ReadyGrantRequest<State>(ResolvedRequest<State>);
pub struct ReadyGuardRequest<State>(ResolvedRequest<State>);

impl<State> WebRequest for ResolvedRequest<State> {
    type Error = OAuthError;
    type Response = HttpResponse;

     fn query(&mut self) -> Result<Cow<HashMap<String, Vec<String>>>, ()> {
         self.query.as_ref().map(Cow::Borrowed).map_err(|_| ())
     }

     fn urlbody(&mut self) -> Result<Cow<HashMap<String, Vec<String>>>, ()> {
         self.body.as_ref().map(Cow::Borrowed).map_err(|_| ())
     }

     fn authheader(&mut self) -> Result<Option<Cow<str>>, ()>{
         match &self.authorization {
             &Ok(Some(ref string)) => Ok(Some(Cow::Borrowed(string))),
             &Ok(None) => Ok(None),
             &Err(_) => Err(())
         }
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

impl<State> ResolvedRequest<State> {
    fn headers_only(request: HttpRequest<State>) -> Self {
        let authorization = match request.headers().get("Authorization").map(|header| header.to_str()) {
            None => Ok(None),
            Some(Ok(as_str)) => Ok(Some(as_str.to_string())),
            Some(Err(_)) => Err(())
        };
        let query = request
            .query()
            .iter()
            .map(|&(ref key, ref val)| (key.clone().into_owned(), vec![val.clone().into_owned()]))
            .collect();
        ResolvedRequest {
            request: request,
            authorization: authorization,
            query: Ok(query),
            body: Err(()),
        }
    }

    fn with_body(request: HttpRequest<State>, body: HashMap<String, String>) -> Self {
        let mut resolved = Self::headers_only(request);
        resolved.body = Ok(body
            .into_iter()
            .map(|(key, val)| (key, vec![val]))
            .collect());
        resolved
    }
}

struct ResolvedOwnerAuthorization<A>(A);

impl<A, State> OwnerAuthorizer<ResolvedRequest<State>> for ResolvedOwnerAuthorization<A>
where A: Fn(&HttpRequest<State>, &PreGrant) -> Result<(Authentication, HttpResponse), OAuthError> {
    fn get_owner_authorization(&self, request: &mut ResolvedRequest<State>, grant: &PreGrant)
    -> Result<(Authentication, HttpResponse), OAuthError> {
        self.0(&request.request, grant)
    }
}

impl<State> Future for AuthorizationCodeRequest<State> {
    type Item = ReadyAuthorizationCodeRequest<State>;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let resolved = ResolvedRequest::headers_only(self.request.take().unwrap());
        Ok(Async::Ready(ReadyAuthorizationCodeRequest(resolved)))
    }
}


impl<State> Future for GrantRequest<State> {
    type Item = ReadyGrantRequest<State>;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.body.poll() {
            Ok(Async::Ready(body)) => {
                let resolved = ResolvedRequest::with_body(self.request.take().unwrap(), body);
                Ok(Async::Ready(ReadyGrantRequest(resolved)))
            },
            Ok(Async::NotReady) => Ok(Async::NotReady),

            // Not a valid url encoded body
            Err(err) => Err(OAuthError::AccessDenied),
        }
    }
}

impl<State> Future for GuardRequest<State> {
    type Item = ReadyGuardRequest<State>;
    type Error = OAuthError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let resolved = ResolvedRequest::headers_only(self.request.take().unwrap());
        Ok(Async::Ready(ReadyGuardRequest(resolved)))
    }
}

impl<State> ReadyAuthorizationCodeRequest<State> {
    pub fn handle<A>(self, flow: AuthorizationFlow, authorizer: A) -> Result<HttpResponse, OAuthError>
    where
        A: Fn(&HttpRequest<State>, &PreGrant) -> Result<(Authentication, HttpResponse), OAuthError> {
        flow.handle(self.0, &ResolvedOwnerAuthorization(authorizer))
    }

    pub fn state(&self) -> &State {
        self.0.request.state()
    }
}

impl<State> ReadyGrantRequest<State> {
    pub fn handle(self, flow: GrantFlow) -> Result<HttpResponse, OAuthError> {
        flow.handle(self.0)
    }

    pub fn state(&self) -> &State {
        self.0.request.state()
    }
}

impl<State> ReadyGuardRequest<State> {
    pub fn handle(self, flow: AccessFlow) -> Result<(), OAuthError> {
        flow.handle(self.0)
    }

    pub fn state(&self) -> &State {
        self.0.request.state()
    }
}
