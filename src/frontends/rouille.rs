//! Offers bindings for the code_grant module with rouille servers.
//!
//! Following the simplistic and minimal style of rouille, this module defines only the
//! implementations for `WebRequest` and `WebResponse` and re-exports the available flows.
extern crate rouille;
extern crate serde_urlencoded;

use std::borrow::Cow;

use code_grant::endpoint::{QueryParameter, WebRequest, WebResponse};

use self::rouille::{Request, Response, ResponseBody};
use url::Url;

// In the spirit of simplicity, this module does not implement any wrapper structures.  In order to
// allow efficient and intuitive usage, we simply re-export common structures.
pub use frontends::simple::endpoint::{FnSolicitor, Generic as GenericEndpoint, Vacant};

/// Something went wrong with the rouille http request or response.
#[derive(Debug)]
pub enum WebError {
    /// A parameter was encoded incorrectly.
    ///
    /// This may happen for example due to a query parameter that is not valid utf8 when the query
    /// parameters are necessary for OAuth processing.
    Encoding,
}

impl<'a> WebRequest for &'a Request {
    type Error = WebError;
    type Response = Response;

    fn query(&mut self) -> Result<Cow<QueryParameter + 'static>, Self::Error> {
        let query = self.raw_query_string();
        let data = serde_urlencoded::from_str(query)
            .map_err(|_| WebError::Encoding)?;
        Ok(Cow::Owned(data))
    }

    fn urlbody(&mut self) -> Result<Cow<QueryParameter + 'static>, Self::Error> {
        match self.header("Content-Type") {
            None | Some("application/x-www-form-urlencoded") => (),
            _ => return Err(WebError::Encoding),
        }

        let body = self.data().ok_or(WebError::Encoding)?;
        let data = serde_urlencoded::from_reader(body)
            .map_err(|_| WebError::Encoding)?;
        Ok(Cow::Owned(data))
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, Self::Error> {
        Ok(self.header("Authorization").map(|st| st.into()))
    }
}

impl WebResponse for Response {
    type Error = WebError;

    fn ok(&mut self) -> Result<(), Self::Error> {
        self.status_code = 200;
        Ok(())
    }

    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> {
        self.status_code = 302;
        self.headers.retain(|header| !header.0.eq_ignore_ascii_case("Location"));
        self.headers.push(("Location".into(), url.into_string().into()));
        Ok(())
    }

    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.status_code = 400;
        Ok(())
    }

    fn unauthorized(&mut self, kind: &str) -> Result<(), Self::Error> {
        self.status_code = 401;
        self.headers.retain(|header| !header.0.eq_ignore_ascii_case("www-authenticate"));
        self.headers.push(("WWW-Authenticate".into(), kind.to_string().into()));
        Ok(())
    }

    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> {
        self.headers.retain(|header| !header.0.eq_ignore_ascii_case("Content-Type"));
        self.headers.push(("Content-Type".into(), "text/plain".into()));
        self.data = ResponseBody::from_string(text);
        Ok(())
    }

    fn body_json(&mut self, data: &str) -> Result<(), Self::Error> {
        self.headers.retain(|header| !header.0.eq_ignore_ascii_case("Content-Type"));
        self.headers.push(("Content-Type".into(), "application/json".into()));
        self.data = ResponseBody::from_string(data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn multi_query() {
        let mut request = &Request::fake_http("GET", "/authorize?fine=val&param=a&param=b", vec![], vec![]);
        let query = WebRequest::query(&mut request).unwrap();

        assert_eq!(Some(Cow::Borrowed("val")), query.unique_value("fine"));
        assert_eq!(None, query.unique_value("param"));
    }
}
