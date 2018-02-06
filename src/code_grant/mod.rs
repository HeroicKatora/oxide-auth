//! Adds frontend and backend for the authorization code flow.
//!
//! The backend is largely independent of the communication protocol used and will require the
//! necessary interfaces via traits. This makes it possible to swap out data structures used for
//! most basic operations such as validating clients, issuing bearer tokens, asserting the validity
//! of requests while also performing request parsing and validation in a separate step.
//!
//! In large, the frontend module is responsible for defining a clear interface usable by different
//! transport providers, http server libraries as well as potentially others, and the format of the
//! used transport (based on HTTP because of the strong coupling in the rfc) while the backend is
//! concerned with the logic of handling such requests.
//!
//! Consequently, the return types of the backend are not HTTP responses but rather contain the
//! necessary information to form such responses. The frontend will then convert these actions
//! to specific responses, while encouraging implementations not to leak internal logging
//! information to outside parties through utilization of the implemented traits.

pub mod backend;
pub mod error;
pub mod frontend;
pub mod extensions;

#[cfg(test)]
mod tests;

/// Commonly used items, for clobber imports.
pub mod prelude {
    pub use primitives::prelude::*;
    pub use super::backend::{CodeRef, IssuerRef, GuardRef};
}
