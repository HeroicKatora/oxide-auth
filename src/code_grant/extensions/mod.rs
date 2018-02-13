//! Provides hooks for standard or custom extensions to the OAuth process.

use super::backend::{AccessTokenRequest, CodeRequest};
use primitives::grant::{Extension, GrantExtension};

/// An extension reacting to an initial authorization code request.
pub trait CodeExtension: GrantExtension {
    /// Provides data for this request of signals faulty data.
    ///
    /// There may be two main types of extensions:
    /// - Extensions storing additional information about the client
    /// - Validators asserting additional requirements
    ///
    /// Derived information which needs to be bound to the returned grant can be stored in an
    /// encoded form by returning `Ok(extension_data)` while errors can be signaled via `Err(())`.
    /// Extensions can also store their pure existance by initializing the extension struct without
    /// data. Specifically, the data can be used in a corresponding `AccessTokenExtension`.
    fn extend_code(&self, &CodeRequest) -> Result<Option<Extension>, ()>;
}

/// An extension reacting to an access token request with a provided access token.
pub trait AccessTokenExtension: GrantExtension {
    /// Process an access token request, utilizing the extensions stored data if any.
    ///
    /// The semantics are equivalent to that of `CodeExtension` except that any data which was
    /// returned as a response to the authorization code request is provided as an additional
    /// parameter.
    ///
    /// Data returned here is currently not processed anywhere [WIP].
    fn extend_access_token(&self, &AccessTokenRequest, Option<Extension>)
        -> Result<Option<Extension>, ()>;
}

impl<'a> GrantExtension for &'a CodeExtension {
    fn identifier(&self) -> &'static str {
        (*self).identifier()
    }
}

impl<'a> GrantExtension for &'a AccessTokenExtension {
    fn identifier(&self) -> &'static str {
        (*self).identifier()
    }
}

mod pkce;

pub use self::pkce::Pkce;
