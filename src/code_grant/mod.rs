//! Adds frontend and backend for the authorization code flow.
//!
//! The backend is largely independent of the communication protocol used and will require the
//! necessary interfaces via traits. This makes it possible to swap out data structures used for
//! most basic operations such as validating clients, issuing bearer tokens, asserting the validity
//! of requests while also performing request parsing and validation in a separate step.
//!
//! In large, the frontend is responsible for ensuring the data conforms to internal data types
//! (`url::Url`, `self::scope::Scope`, etc.) and the format of the used transport (the rfc only
//! specifies HTTP) while the backend is concerned with the logic of handling such requests.
//! Consequently, the return types of the backend are not HTTP responses but rather contain the
//! necessary information to form such responses. Again the frontend will then convert these actions
//! to responses, encouraging implementations not to leak internal logging information to outside
//! parties.
//!

pub mod backend;
pub mod error;
pub mod frontend;

#[cfg(test)]
mod tests;

pub use primitives::scope::Scope;

pub mod prelude {
    pub use primitives::prelude::*;
    pub use super::backend::{CodeRef, IssuerRef, GuardRef};
}
