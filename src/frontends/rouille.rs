//! Offers bindings for the code_grant module with rouille servers.
//!
//! Following the simplistic and minimal style of rouille, this module defines only the
//! implementations for `WebRequest` and `WebResponse` and re-exports the available flows.
extern crate rouille;
extern crate serde_urlencoded;

use code_grant::frontend::{QueryParameter, SingleValueQuery, WebRequest, WebResponse};

// In the spirit of simplicity, this module does not implement any wrapper structures.  In order to
// allow efficient and intuitive usage, we simply re-export common structures.
pub use code_grant::frontend::{AccessFlow, AuthorizationFlow, GrantFlow};
pub use code_grant::frontend::{OAuthError, OwnerAuthorizer, OwnerAuthorization};
pub use code_grant::prelude::*;

use std::borrow::Cow;
use std::collections::HashMap;

use self::rouille::{Request, Response};
use url::Url;

impl<'a> WebRequest for &'a Request {
    type Error = OAuthError;
    type Response = Response;

    fn query<'s>(&'s mut self) -> Result<QueryParameter<'s>, ()> {
        let query = self.raw_query_string();
        let data: HashMap<Cow<'s, str>, Cow<'s, str>>
            = serde_urlencoded::from_str(query).map_err(|_| ())?;
        Ok(QueryParameter::SingleValue(
            SingleValueQuery::CowValue(Cow::Owned(data))))
    }

    fn urlbody(&mut self) -> Result<QueryParameter, ()> {
        match self.header("Content-Type") {
            None | Some("application/x-www-form-urlencoded") => (),
            _ => return Err(()),
        }

        let body = self.data().ok_or(())?;
        let data: HashMap<String, String> = serde_urlencoded::from_reader(body).map_err(|_| ())?;
        Ok(QueryParameter::SingleValue(
            SingleValueQuery::StringValue(Cow::Owned(data))))
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, ()> {
        Ok(self.header("Authorization").map(|st| st.into()))
    }
}

impl WebResponse for Response {
    type Error = OAuthError;

    fn redirect(url: Url) -> Result<Response, OAuthError> {
        Ok(Response::redirect_302(Cow::Owned(url.to_string())))
    }

    fn text(text: &str) -> Result<Response, OAuthError> {
        Ok(Response::text(text))
    }

    fn json(data: &str) -> Result<Response, OAuthError> {
        Ok(Response::from_data("application/json", data))
    }

    fn as_client_error(self) -> Result<Self, OAuthError> {
        Ok(self.with_status_code(400))
    }

    fn as_unauthorized(self) -> Result<Self, OAuthError> {
        Ok(self.with_status_code(401))
    }

    fn with_authorization(self, kind: &str) -> Result<Self, OAuthError> {
        Ok(self
            .with_status_code(401)
            .with_unique_header("WWW-Authenticate", Cow::Owned(kind.to_string())))
    }
}

impl<'a, F> OwnerAuthorizer<&'a Request> for F
where F: FnOnce(&'a Request, &PreGrant) -> OwnerAuthorization<Response> {
    fn check_authorization(self, request: &'a Request, pre_grant: &PreGrant)
    -> OwnerAuthorization<Response> {
        self(request, pre_grant)
    }
}
