//! Available backend algorithms.
//!
//! The backend codifies the requirements for the  from the [RFC 6749] into types and functions as
//! safely as possible. The result of the backend are abstract results, actions which should be
//! executed or relayed by the frontend using its available types. Abstract in this sense means
//! that the responses from the backend are not generic on an input type.
//!
//! Another consideration is the possibility of reusing some components with other oauth schemes.
//! In this way, the backend is used to group necessary types and as an interface to implementors,
//! to be able to infer the range of applicable end effectors (i.e. authorizers, issuer,
//! registrars).
//!
//! ## Usage
//!
//! For all purposes that offer user interaction through an access point, you should probably have
//! a look at the encapsulation provided by [`endpoint`] instead. You should only fallback to this
//! if the flows provided there are too generic (unlikely) or your use case makes an [`Endpoint`]
//! implementation impossible.
//!
//! ## Limitations
//!
//! The only supported authentication method for clients is password based. This is not to be
//! confused with users in the sense of people registering accounts on a social media platform. In
//! OAuth nomenclature, those are resource owners while a client is a user of a (Bearer) token.
//!
//! [RFC 6479]: https://tools.ietf.org/html/rfc6749
//! [`endpoint`]: ../endpoint/index.html
//! [`Endpoint`]: ../endpoint/trait.Endpoint.html

pub mod access_token;
pub mod authorization;
pub mod error;
pub mod extensions;
pub mod refresh;
pub mod resource;
