//! Offers bindings for the code_grant module with iron servers.
//!
//! ## Hello world
//!
//! ```no_run
//! # extern crate oxide_auth;
//! # extern crate iron;
//! extern crate router;
//! use oxide_auth::frontends::iron::prelude::*;
//! use iron::prelude::*;
//!
//! use std::thread;
//! use iron::modifier::Modifier;
//! use router::Router;
//!
//! /// Example of a main function of a iron server supporting oauth.
//! pub fn main() {
//!     // Create the main token instance, a code_granter with an iron frontend.
//!     let ohandler = IronGranter::new(
//!         // Stores clients in a simple in-memory hash map.
//!         ClientMap::new(),
//!         // Authorization tokens are 16 byte random keys to a memory hash map.
//!         Storage::new(RandomGenerator::new(16)),
//!         // Bearer tokens are signed (but not encrypted) using a passphrase.
//!         TokenSigner::ephemeral());
//!
//!     // Register a dummy client instance
//!     let client = Client::public("LocalClient", // Client id
//!         "http://localhost:8021/endpoint".parse().unwrap(), // Redirection url
//!         "default".parse().unwrap()); // Allowed client scope
//!     ohandler.registrar().unwrap().register_client(client);
//!
//!     // Create a router and bind the relevant pages
//!     let mut router = Router::new();
//!     router.get("/authorize", ohandler.authorize(MethodAuthorizer(handle_get)), "authorize");
//!     router.post("/authorize", ohandler.authorize(IronOwnerAuthorizer(handle_post)),
//!         "authorize");
//!     router.post("/token", ohandler.token(), "token");
//!
//!     let mut protected = iron::Chain::new(|_: &mut Request| {
//!         Ok(Response::with((iron::status::Ok, "Hello World!")))
//!     });
//!     // Set up a protected resource, only accessible with a token with `default scope`.
//!     protected.link_before(ohandler.guard(vec!["default".parse::<Scope>().unwrap()]));
//!     // Instead of an error, show a warning and instructions
//!     protected.link_after(HelpfulAuthorizationError());
//!     router.get("/", protected, "protected");
//!
//!     // Start the server
//!     let server = thread::spawn(||
//!         iron::Iron::new(router).http("localhost:8020").unwrap());
//!
//!     server.join().expect("Failed to run");
//! }
//!
//! /// This should display a page to the user asking for his permission to proceed.
//! /// You can use the Response in Ok to achieve this.
//! fn handle_get(_: &mut Request, auth: &PreGrant) -> OwnerAuthorization<Response> {
//!     unimplemented!();
//! }
//!
//! /// This shows the second style of authentication handler, a iron::Handler compatible form.
//! /// Allows composition with other libraries or frameworks built around iron.
//! fn handle_post(req: &mut Request) -> IronResult<Response> {
//!     unimplemented!();
//! }
//!
//! /// Show a message to unauthorized requests of the protected resource.
//! struct HelpfulAuthorizationError();
//!
//! impl iron::middleware::AfterMiddleware for HelpfulAuthorizationError {
//!     fn catch(&self, _: &mut Request, err: iron::IronError) -> IronResult<Response> {
//!         if !err.error.is::<OAuthError>() {
//!            return Err(err);
//!         }
//!         let mut response = err.response;
//!         let text =
//!             "<html>
//! 	    This page is only accessible with an oauth token, scope <em>default</em>.
//!             </html>";
//!         text.modify(&mut response);
//!         iron::modifiers::Header(iron::headers::ContentType::html()).modify(&mut response);
//!         Ok(response)
//!     }
//! }
//!
//! ```
extern crate iron;

use std::borrow::Cow;

use endpoint::{QueryParameter, WebRequest, WebResponse};

use self::iron::{Request, Response};
use self::iron::headers;
use self::iron::status::Status;
use url::Url;

/// Errors while decoding requests.
pub enum Error { 
    /// Generally describes a malformed request.
    BadRequest,
}

/// Requests are handed as mutable reference to the underlying object.
impl<'a, 'b, 'c: 'b> WebRequest for &'a mut Request<'b, 'c> {
    type Response = Response;
    type Error = Error;

    fn query(&mut self) -> Result<Cow<QueryParameter + 'static>, Self::Error> {
        serde_urlencoded::from_str(self.url.query().unwrap_or(""))
            .map_err(|_| Error::BadRequest)
            .map(Cow::Owned)
    }

    fn urlbody(&mut self) -> Result<Cow<QueryParameter + 'static>, Self::Error> {
        let content_type = self.headers.get::<headers::ContentType>();
        let formatted = content_type
            .map(|ct| ct == &headers::ContentType::form_url_encoded())
            .unwrap_or(false);
        if !formatted {
            return Err(Error::BadRequest)
        }

        serde_urlencoded::from_reader(&mut self.body)
            .map_err(|_| Error::BadRequest)
            .map(Cow::Owned)
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, Self::Error> {
        // Get the raw header.
        match self.headers.get::<headers::Authorization<String>>() {
            None => Ok(None),
            Some(header) => Ok(Some(Cow::Borrowed(&header.0))),
        }
    }
}

impl WebResponse for Response {
    type Error = Error;

    fn ok(&mut self) -> Result<(), Self::Error> { 
        self.status = Some(Status::Ok);
        Ok(())
    }

    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> { 
        self.status = Some(Status::Found);
        self.headers.set(headers::Location(url.into_string()));
        Ok(())
    }

    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.status = Some(Status::BadRequest);
        Ok(())
    }

    fn unauthorized(&mut self, header_value: &str) -> Result<(), Self::Error> { 
        self.status = Some(Status::Unauthorized);
        let value_owned = header_value.as_bytes().to_vec();
        self.headers.set_raw("WWW-Authenticate", vec![value_owned]);
        Ok(())
    }

    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> { 
        self.headers.set(headers::ContentType::plaintext());
        self.body = Some(Box::new(text.to_string()));
        Ok(())
    }

    fn body_json(&mut self, data: &str) -> Result<(), Self::Error> { 
        self.headers.set(headers::ContentType::json());
        self.body = Some(Box::new(data.to_string()));
        Ok(())
    }
}
