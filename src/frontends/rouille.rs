//! Offers bindings for the code_grant module with rouille servers.
//!
//! Following the simplistic and minimal style of rouille, this module defines only the
//! implementations for `WebRequest` and `WebResponse` and re-exports the available flows.
extern crate rouille;
extern crate serde_urlencoded;

use code_grant::frontend::{WebRequest, WebResponse};

// In the spirit of simplicity, this module does not implement any wrapper structures.  In order to
// allow efficient and intuitive usage, we simply re-export common structures.
pub use code_grant::frontend::{AccessFlow, AuthorizationFlow, GrantFlow};
pub use code_grant::frontend::{Authentication, OAuthError, OwnerAuthorizer};
pub use code_grant::prelude::*;

use std::borrow::Cow;
use std::collections::HashMap;

use self::rouille::{Request, Response};
use url::Url;

impl<'a> WebRequest for &'a Request {
    type Error = OAuthError;
    type Response = Response;

    fn query(&mut self) -> Result<Cow<HashMap<String, Vec<String>>>, ()> {
        let query = self.raw_query_string();
        let data: HashMap<String, String> = serde_urlencoded::from_str(query).map_err(|_| ())?;
        let data = data.into_iter()
            .map(|(key, value)| (key, vec![value]))
            .collect();
        Ok(Cow::Owned(data))
    }

    fn urlbody(&mut self) -> Result<Cow<HashMap<String, Vec<String>>>, ()> {
        match self.header("Content-Type") {
            None | Some("application/x-www-form-urlencoded") => (),
            _ => return Err(()),
        }

        let body = self.data().ok_or(())?;
        let data: HashMap<String, String> = serde_urlencoded::from_reader(body).map_err(|_| ())?;
        let data = data.into_iter()
            .map(|(key, value)| (key, vec![value]))
            .collect();
        Ok(Cow::Owned(data))
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
where
    F: for<'r, 's> Fn(&'r Request, &'s PreGrant) -> Result<(Authentication, Response), OAuthError> {

    fn get_owner_authorization(&self, request: &mut &'a Request, grant: &PreGrant)
    -> Result<(Authentication, Response), OAuthError> {
        self(request, grant)
    }
}
