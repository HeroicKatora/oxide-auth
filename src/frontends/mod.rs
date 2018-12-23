//! Fully implemented frontends.
//!
//! Frontends are glue adapters from other http server crates to the interface exposed by
//! individual methods offered in this crate. The exact usage of the frontend varies from
//! implementation to implementation. Composability and usability are the main concerns for
//! frontends, full feature support is a secondary concern.
//!
//! Guide
//! ------
//!
//! All frontend implementations should start with two closely related traits: [`WebRequest`] and
//! [`WebResponse`].  These central interfaces are used to interact with the libraries supported
//! token flows (currently only authorization code grant).
//!
//! Lets step through those implementations one by one.  As an example request type, let's pretend
//! that the web interface consists of the following types:
//!
//! ```
//! use std::collections::HashMap;
//! struct ExampleRequest {
//!     /// The query part of the retrieved uri, conveniently pre-parsed.
//!     query: Option<HashMap<String, String>>,
//!
//!     /// The value of the authorization header if any was wet.
//!     authorization_header: Option<String>,
//!
//!     /// The body of the request, only if its content type was `application/x-form-urlencoded`
//!     urlbody: Option<HashMap<String, String>>,
//! }
//!
//! struct ExampleResponse {
//!     /// The http status code, 200 for OK
//!     status: u16,
//!
//!     /// The Content or MIME type of the body
//!     content_type: Option<String>,
//!
//!     /// The value of the `WWW-Authenticate` header if any
//!     www_authenticate: Option<String>,
//!
//!     /// The value of the `Location` header if any
//!     location: Option<String>,
//!
//!     /// The body sent
//!     body: Option<String>,
//! }
//! # fn main() { }
//! ```
//! This is obviously incredibly simplified but will showcase the most valuable features of this
//! library. Let's implement the required traits:
//!
//! ```
//! # use std::collections::HashMap;
//! # struct ExampleRequest {
//! #    /// The query part of the retrieved uri, conveniently pre-parsed.
//! #    query: HashMap<String, String>,
//! #
//! #    /// The value of the authorization header if any was wet.
//! #    authorization_header: Option<String>,
//! #
//! #    /// The body of the request, only if its content type was `application/x-form-urlencoded`
//! #    urlbody: Option<HashMap<String, String>>,
//! # }
//! #
//! # struct ExampleResponse {
//! #    /// The http status code, 200 for OK
//! #    status: u16,
//! #
//! #    /// The Content or MIME type of the body
//! #    content_type: Option<String>,
//! #
//! #    /// The value of the `WWW-Authenticate` header if any
//! #    www_authenticate: Option<String>,
//! #
//! #    /// The value of the `Location` header if any
//! #    location: Option<String>,
//! #
//! #    /// The body sent
//! #    body: Option<String>,
//! # }
//! # extern crate oxide_auth;
//! use oxide_auth::frontends::dev::*;
//! impl WebRequest for ExampleRequest {
//!     // Declare the corresponding response type.
//!     type Response = ExampleResponse;
//!
//!     // Our internal frontends error type is `OAuthError`
//!     type Error = OAuthError;
//!
//!     fn query(&mut self) -> Result<Cow<QueryParameter + 'static>, OAuthError> {
//!         Ok(Cow::Borrowed(&self.query))
//!     }
//!
//!     fn urlbody(&mut self) -> Result<Cow<QueryParameter + 'static>, OAuthError> {
//!         self.urlbody.as_ref()
//!             .map(|body| Cow::Borrowed(body as &QueryParameter))
//!             .ok_or(OAuthError::PrimitiveError)
//!     }
//!
//!     fn authheader(&mut self) -> Result<Option<Cow<str>>, OAuthError> {
//!         // Borrow the data if it exists, else we had no header. No error cases.
//!         Ok(self.authorization_header.as_ref().map(|string| string.as_str().into()))
//!     }
//! }
//!
//! impl WebResponse for ExampleResponse {
//!     // Redeclare our error type, those two must be the same.
//!     type Error = OAuthError;
//!
//!     fn ok(&mut self) -> Result<(), OAuthError> {
//!         self.status = 200;
//!         self.www_authenticate = None;
//!         self.location = None;
//!         Ok(())
//!     }
//!
//!     fn redirect(&mut self, target: Url) -> Result<(), OAuthError> {
//!         self.status = 302;
//!         self.www_authenticate = None;
//!         self.location = Some(target.into_string());
//!         Ok(())
//!     }
//!
//!     fn client_error(&mut self) -> Result<(), OAuthError> {
//!         self.status = 400;
//!         self.www_authenticate = None;
//!         self.location = None;
//!         Ok(())
//!     }
//!
//!     fn unauthorized(&mut self, www_authenticate: &str) -> Result<(), OAuthError> {
//!         self.status = 401;
//!         self.www_authenticate = Some(www_authenticate.to_string());
//!         self.location = None;
//!         Ok(())
//!     }
//!
//!     fn body_text(&mut self, text: &str) -> Result<(), OAuthError> {
//!         self.body = Some(text.to_string());
//!         self.content_type = Some("text/plain".to_string());
//!         Ok(())
//!     }
//!
//!     fn body_json(&mut self, json: &str) -> Result<(), OAuthError> {
//!         self.body = Some(json.to_string());
//!         self.content_type = Some("application/json".to_string());
//!         Ok(())
//!     }
//! }
//!
//! # fn main() {}
//! ```
//!
//! And we're done, the library is fully useable. In fact, the implementation for `rouille` is
//! almost the same as what we just did. All that is missing is your web servers main loop to drive
//! the thing and a look into the `code_grant::frontend::{AuthorizationFlow, GrantFlow, AccessFlow}`
//! which will explain the usage of the above traits in the context of the Authorization Code Grant.
//!
//! Of course, this style might not the intended way for some server libraries. In this case, you
//! may want to provide additional wrappers.
//!

pub mod simple;

#[cfg(feature = "actix-frontend")]
pub mod actix;
// #[cfg(feature = "gotham-frontend")]
// pub mod gotham;
// #[cfg(feature = "iron-frontend")]
// pub mod iron;
#[cfg(feature = "rouille-frontend")]
pub mod rouille;

/// Includes useful for writing frontends.
pub mod dev {
    pub use std::borrow::Cow;
    pub use url::Url;
    pub use code_grant::endpoint::{Endpoint, WebRequest, WebResponse};
    pub use code_grant::endpoint::{OAuthError, OwnerSolicitor, QueryParameter};
}
