//! # oxide-auth
//!
//! A OAuth2 server library, for use in combination with actix-web or other frontends, featuring a
//! set of configurable and pluggable backends.
//!
//! ## About
//!
//! `oxide-auth` aims at providing a comprehensive and extensible interface to managing oauth2
//! tokens on a server. While the core package is agnostic of the used frontend, an optional actix
//! adaptor is provided with the default configuration. Through an interface designed with traits,
//! the frontend is as easily pluggable as the backend.
//!
//! The `actix` frontend, included as a default feature, provides bindings to create an endpoint in
//! `actix-web`.
//!
//! ## Example
//!
//! A fully featured [web server example][actix example] is realized with actix.
//!
//! > `$ cargo run --example actix`
//!
//! # Use cases
//!
//! Versatility is a primary goal.  Consequently, there are several different scenarios in which
//! this library will be useful.  Of course all of them are related to server side use of OAuth2
//! protocol.
//!
//! ## Create a web server with OAuth security
//!
//! So you want to build a new OAuth provider? Instead of only relying on tokens provided by other
//! large internet entities, you want to make your own tokens? This library and OAuth2 was built to
//! safely provide authorization tokens to third-party clients, distinct from your users that
//! authorize them. Examples of this use case: A web facing data portal, automation endpoints (in
//! the style of Reddit or Discord), or even to restrict the authorization of different components
//! of your own software by applying these techniques to your `REST` backend.
//!
//! This library can be integrated into several different web server libraries.  Most prominently
//! `actix-web`, `rocket` and `iron`.  These frontends allow you to easily answer OAuth requests and
//! secure protected resources, utilizing the library provided http request types.  Some provide
//! additional abstractions for an integrated feeling.
//!
//! A complete list can be found in the [`frontends`] module.
//!
//! You can also use this library with any HTTP frontend, see [`frontends::simple`].
//!
//! ## Custom Frontends
//!
//! A key feature is the ability to add your own frontend without jeopardizing safety requirements.
//! For example to add your in-house `REST` library! This requires custom, related implementations
//! of [`WebRequest`] and [`WebResponse`]. _WARNING_: Custom frontends MUST ensure a secure
//! communication layer with confidential clients. This means using TLS for communication over
//! https.
//!
//! For more information, see the documentation of [`endpoint`] and [`frontends`].
//!
//! ## Using the primitives
//!
//! All [`primitives`] can be used independently of the frontend modules.  This makes them reusable
//! for other authentication methods.  But this works the other way around as well.  Your own
//! implementations of these primitives can be used directly in conjuction with all frontends
//! (although some may impose `Send` or `Sync` constraits due to limitations of the web library).
//!
//! [`WebRequest`]: endpoint/trait.WebRequest.html
//! [`WebResponse`]: endpoint/trait.WebResponse.html
//! [`endpoint`]: endpoint/index.html
//! [`frontends`]: frontends/index.html
//! [`frontends::simple`]: frontends/simple/index.html
//! [`primitives`]: primitives/index.html
//! [actix example]: https://github.com/HeroicKatora/oxide-auth/blob/master/examples/actix-example/src/main.rs
//!
#![warn(missing_docs)]

extern crate oxide_auth_core;

#[cfg(feature = "oxide-auth-actix")]
extern crate oxide_auth_actix;

#[cfg(feature = "oxide-auth-iron")]
extern crate oxide_auth_iron;

#[cfg(feature = "oxide-auth-rocket")]
extern crate oxide_auth_rocket;

#[cfg(feature = "oxide-auth-rouille")]
extern crate oxide_auth_rouille;

pub use oxide_auth_core::{code_grant, endpoint, primitives};

pub mod frontends {
    //! Fully implemented frontends.
    //!
    //! Frontends are glue adapters from other http server crates to the interface exposed by
    //! individual methods offered in this crate. The exact usage of the frontend varies from
    //! implementation to implementation. Composability and usability are the main concerns for
    //! frontends, full feature support is a secondary concern.
    //!
    //! Usage
    //! -----
    //!
    //! First you need to enable the correct feature flag. Note that for the convenience of viewing
    //! this documentation, the version on `docs.rs` has all features enabled. The following frontends
    //! require the following features:
    //!
    //! * `simple`: None, this can also be a basis for other implementations
    //! * `actix`: `actix-frontend`
    //! * `rouille`: `rouille-frontend`
    //! * `rocket`: `rocket-frontend`
    //!
    //! Guide
    //! ------
    //!
    //! All frontend implementations should start with two closely related traits: [`WebRequest`](endpoint/trait.WebRequest.html) and
    //! [`WebResponse`](endpoint/trait.WebResponse.html).  These central interfaces are used to interact with the libraries supported
    //! token flows (currently only authorization code grant).
    //!
    //! Lets step through those implementations one by one.  As an example request type, let's pretend
    //! that the web interface consists of the following types:
    //!
    //! ```
    //! use oxide_auth::frontends::dev::*;
    //!
    //! struct ExampleRequest {
    //!     /// The query part of the retrieved uri, conveniently pre-parsed.
    //!     query: NormalizedParameter,
    //!
    //!     /// The value of the authorization header if any was wet.
    //!     authorization_header: Option<String>,
    //!
    //!     /// A correctly interpreted version of the body of the request, only if its content type
    //!     /// `application/x-form-urlencoded`
    //!     urlbody: Option<NormalizedParameter>,
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
    //! use oxide_auth::frontends::dev::*;
    //! # struct ExampleRequest {
    //! #    /// The query part of the retrieved uri, conveniently pre-parsed.
    //! #    query: NormalizedParameter,
    //! #
    //! #    /// The value of the authorization header if any was wet.
    //! #    authorization_header: Option<String>,
    //! #
    //! #    /// The body of the request, only if its content type was `application/x-form-urlencoded`
    //! #    urlbody: Option<NormalizedParameter>,
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
    //!     // Redeclare our error type as in the request, those two must be the same.
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
    //! And we're done, the library is fully useable. In fact, the implementation for `simple` is
    //! almost the same as what we just did with some minor extras. All that is missing is your web
    //! servers main loop to drive the thing and a look into the
    //! [`code_grant::endpoint::{AuthorizationFlow, GrantFlow, AccessFlow}`] which will explain the usage
    //! of the above traits in the context of the Authorization Code Grant.
    //!
    //! Of course, this style might not the intended way for some server libraries. In this case, you
    //! may want to provide additional wrappers. The `actix` frontend adds utilities for abstracting
    //! futures and actor messaging, for example.
    //!
    //! [`code_grant::endpoint::{AuthorizationFlow, GrantFlow, AccessFlow}`]: ../code_grant/endpoint/index.html
    //!

    pub use oxide_auth_core::frontends::{dev, simple};

    #[cfg(feature = "oxide-auth-actix")]
    pub mod actix {
        //! Bindings and utilities for creating an oauth endpoint with actix.
        //!
        //! Use the provided methods to use code grant methods in an asynchronous fashion, or use an
        //! `AsActor<_>` to create an actor implementing endpoint functionality via messages.
        pub use oxide_auth_actix::{
            access_token, authorization, message, refresh, request, resource, AsActor, OAuth,
            OAuthFailure, OAuthFuture, OAuthRequest, OAuthResponse, OwnerConsent, PreGrant,
            ResourceProtection,
        };
    }

    #[cfg(feature = "oxide-auth-iron")]
    pub mod iron {
        //! Offers bindings for the code_grant module with iron servers.
        //!
        //! ## Hello world
        //!
        pub use oxide_auth_iron::{Error, OAuthError, OAuthRequest, OAuthResponse};
    }

    #[cfg(feature = "oxide-auth-rocket")]
    pub mod rocket {
        //! Adaptions and integration for rocket.
        pub use oxide_auth_rocket::{OAuthFailure, OAuthRequest, OAuthResponse, WebError};
    }

    #[cfg(feature = "oxide-auth-rouille")]
    pub mod rouille {
        //! Offers bindings for the code_grant module with rouille servers.
        //!
        //! Following the simplistic and minimal style of rouille, this module defines only the
        //! implementations for `WebRequest` and `WebResponse` and re-exports the available flows.
        pub use oxide_auth_rouille::{
            FnSolicitor, GenericEndpoint, OAuthRequest, OAuthResponse, Vacant, WebError,
        };
    }
}
