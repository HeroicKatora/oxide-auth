//! Extension systems with no cross-dependencies.
pub use code_grant::authorization::Request as AuthorizationRequest;
pub use code_grant::accesstoken::Request as AccessTokenRequest;

mod pkce;
mod system;

use std::borrow::{Cow, ToOwned};
use std::rc::Rc;
use std::sync::Arc;

pub use self::system::System;
use primitives::grant::{Extension as ExtensionData, GrantExtension};

/// Result of extension processing.
/// FIXME: think of a better name.
#[must_use="This type is similar to std::result::Result and should not be ignored."]
pub enum ExtensionResult {
    /// Allow the request unchanged.
    Ok,

    /// Allow the request and attach additional data to the response.
    Data(ExtensionData),

    /// Do not permit the request.
    Err,
}

/// An extension reacting to an initial authorization code request.
pub trait AuthorizationExtension: GrantExtension {
    /// Provides data for this request or signals faulty data.
    ///
    /// There may be two main types of extensions:
    /// - Extensions storing additional information about the client
    /// - Validators asserting additional requirements
    ///
    /// Derived information which needs to be bound to the returned grant can be stored in an
    /// encoded form by returning `Ok(extension_data)` while errors can be signaled via `Err(())`.
    /// Extensions can also store their pure existance by initializing the extension struct without
    /// data. Specifically, the data can be used in a corresponding `AccessTokenExtension`.
    fn extend_code(&self, &AuthorizationRequest) -> ExtensionResult;
}

/// An extension reacting to an access token request with a provided access token.
pub trait AccessTokenExtension: GrantExtension {
    /// Process an access token request, utilizing the extensions stored data if any.
    ///
    /// The semantics are equivalent to that of `CodeExtension` except that any data which was
    /// returned as a response to the authorization code request is provided as an additional
    /// parameter.
    fn extend_access_token(&self, &AccessTokenRequest, Option<ExtensionData>) -> ExtensionResult;
}

impl<'a, T: AuthorizationExtension + ?Sized> AuthorizationExtension for &'a T {
    fn extend_code(&self, request: &AuthorizationRequest) -> ExtensionResult {
        (**self).extend_code(request)
    }
}

impl<'a, T: AuthorizationExtension + ?Sized> AuthorizationExtension for Cow<'a, T> 
    where T: Clone + ToOwned
{
    fn extend_code(&self, request: &AuthorizationRequest) -> ExtensionResult {
        self.as_ref().extend_code(request)
    }
}

impl<T: AuthorizationExtension + ?Sized> AuthorizationExtension for Box<T> {
    fn extend_code(&self, request: &AuthorizationRequest) -> ExtensionResult {
        (**self).extend_code(request)
    }
}

impl<T: AuthorizationExtension + ?Sized> AuthorizationExtension for Arc<T> {
    fn extend_code(&self, request: &AuthorizationRequest) -> ExtensionResult {
        (**self).extend_code(request)
    }
}

impl<T: AuthorizationExtension + ?Sized> AuthorizationExtension for Rc<T> {
    fn extend_code(&self, request: &AuthorizationRequest) -> ExtensionResult {
        (**self).extend_code(request)
    }
}



impl<'a, T: AccessTokenExtension + ?Sized> AccessTokenExtension for &'a T {
    fn extend_access_token(&self, request: &AccessTokenRequest, data: Option<ExtensionData>) -> ExtensionResult {
        (**self).extend_access_token(request, data)
    }
}

impl<'a, T: AccessTokenExtension + ?Sized> AccessTokenExtension for Cow<'a, T> 
    where T: Clone + ToOwned
{
    fn extend_access_token(&self, request: &AccessTokenRequest, data: Option<ExtensionData>) -> ExtensionResult {
        self.as_ref().extend_access_token(request, data)
    }
}

impl<T: AccessTokenExtension + ?Sized> AccessTokenExtension for Box<T> {
    fn extend_access_token(&self, request: &AccessTokenRequest, data: Option<ExtensionData>) -> ExtensionResult {
        (**self).extend_access_token(request, data)
    }
}

impl<T: AccessTokenExtension + ?Sized> AccessTokenExtension for Arc<T> {
    fn extend_access_token(&self, request: &AccessTokenRequest, data: Option<ExtensionData>) -> ExtensionResult {
        (**self).extend_access_token(request, data)
    }
}

impl<T: AccessTokenExtension + ?Sized> AccessTokenExtension for Rc<T> {
    fn extend_access_token(&self, request: &AccessTokenRequest, data: Option<ExtensionData>) -> ExtensionResult {
        (**self).extend_access_token(request, data)
    }
}
