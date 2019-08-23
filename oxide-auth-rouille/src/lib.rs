//! Offers bindings for the code_grant module with rouille servers.
//!
//! Following the simplistic and minimal style of rouille, this module defines only the
//! implementations for `WebRequest` and `WebResponse` and re-exports the available flows.
extern crate rouille;
extern crate serde_urlencoded;
extern crate url;

use std::borrow::Cow;

use oxide_auth_core::endpoint::{QueryParameter, WebRequest, WebResponse};

use rouille::{Request, Response, ResponseBody};
use url::Url;

// In the spirit of simplicity, this module does not implement any wrapper structures.  In order to
// allow efficient and intuitive usage, we simply re-export common structures.
pub use oxide_auth_core::frontends::simple::endpoint::{
    FnSolicitor, Generic as GenericEndpoint, Vacant,
};

/// Something went wrong with the rouille http request or response.
#[derive(Debug)]
pub enum WebError {
    /// A parameter was encoded incorrectly.
    ///
    /// This may happen for example due to a query parameter that is not valid utf8 when the query
    /// parameters are necessary for OAuth processing.
    Encoding,
}

#[derive(Debug)]
pub struct OAuthRequest<'a>(pub &'a Request);

impl<'a> WebRequest for OAuthRequest<'a> {
    type Error = WebError;
    type Response = OAuthResponse;

    fn query(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
        let query = self.0.raw_query_string();
        let data = serde_urlencoded::from_str(query).map_err(|_| WebError::Encoding)?;
        Ok(Cow::Owned(data))
    }

    fn urlbody(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
        match self.0.header("Content-Type") {
            None | Some("application/x-www-form-urlencoded") => (),
            _ => return Err(WebError::Encoding),
        }

        let body = self.0.data().ok_or(WebError::Encoding)?;
        let data = serde_urlencoded::from_reader(body).map_err(|_| WebError::Encoding)?;
        Ok(Cow::Owned(data))
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, Self::Error> {
        Ok(self.0.header("Authorization").map(|st| st.into()))
    }
}

#[derive(Debug)]
pub struct OAuthResponse(pub Response);

impl From<Response> for OAuthResponse {
    fn from(r: Response) -> Self {
        OAuthResponse(r)
    }
}

impl Into<Response> for OAuthResponse {
    fn into(self) -> Response {
        self.0
    }
}

impl OAuthResponse {
    pub fn empty_404() -> Self {
        OAuthResponse(Response::empty_404())
    }
}

impl WebResponse for OAuthResponse {
    type Error = WebError;

    fn ok(&mut self) -> Result<(), Self::Error> {
        self.0.status_code = 200;
        Ok(())
    }

    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> {
        self.0.status_code = 302;
        self.0
            .headers
            .retain(|header| !header.0.eq_ignore_ascii_case("Location"));
        self.0
            .headers
            .push(("Location".into(), url.into_string().into()));
        Ok(())
    }

    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.0.status_code = 400;
        Ok(())
    }

    fn unauthorized(&mut self, kind: &str) -> Result<(), Self::Error> {
        self.0.status_code = 401;
        self.0
            .headers
            .retain(|header| !header.0.eq_ignore_ascii_case("www-authenticate"));
        self.0
            .headers
            .push(("WWW-Authenticate".into(), kind.to_string().into()));
        Ok(())
    }

    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> {
        self.0
            .headers
            .retain(|header| !header.0.eq_ignore_ascii_case("Content-Type"));
        self.0
            .headers
            .push(("Content-Type".into(), "text/plain".into()));
        self.0.data = ResponseBody::from_string(text);
        Ok(())
    }

    fn body_json(&mut self, data: &str) -> Result<(), Self::Error> {
        self.0
            .headers
            .retain(|header| !header.0.eq_ignore_ascii_case("Content-Type"));
        self.0
            .headers
            .push(("Content-Type".into(), "application/json".into()));
        self.0.data = ResponseBody::from_string(data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_query() {
        let request =
            &Request::fake_http("GET", "/authorize?fine=val&param=a&param=b", vec![], vec![]);
        let mut oauth_request = OAuthRequest(&request);
        let query = WebRequest::query(&mut oauth_request).unwrap();

        assert_eq!(Some(Cow::Borrowed("val")), query.unique_value("fine"));
        assert_eq!(None, query.unique_value("param"));
    }
}
