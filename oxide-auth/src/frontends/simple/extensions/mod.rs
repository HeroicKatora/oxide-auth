//! Basic extension systems.
//!
//! Note that extensions will probably return in `v0.4` but not its preview versions.
pub use crate::code_grant::authorization::Request as AuthorizationRequest;
pub use crate::code_grant::access_token::Request as AccessTokenRequest;

mod extended;
mod pkce;
mod list;

use std::borrow::{Cow, ToOwned};
use std::rc::Rc;
use std::sync::Arc;

pub use self::extended::Extended;
pub use self::pkce::Pkce;
pub use self::list::AddonList;
use crate::primitives::grant::{GrantExtension, Value};

/// Result of extension processing.
#[must_use = "This type is similar to std::result::Result and should not be ignored."]
pub enum AddonResult {
    /// Allow the request unchanged.
    Ok,

    /// Allow the request and attach additional data to the response.
    Data(Value),

    /// Do not permit the request.
    Err,
}

/// An extension reacting to an initial authorization code request.
pub trait AuthorizationAddon: GrantExtension {
    /// Provides data for this request or signals faulty data.
    ///
    /// There may be two main types of extensions:
    /// - Extensions storing additional information about the client
    /// - Validators asserting additional requirements
    ///
    /// Derived information which needs to be bound to the returned grant can be stored in an
    /// encoded form by returning `Ok(extension_data)` while errors can be signaled via `Err(())`.
    /// Extensions can also store their pure existence by initializing the extension struct without
    /// data. Specifically, the data can be used in a corresponding `AccessTokenExtension`.
    fn execute(&self, request: &dyn AuthorizationRequest) -> AddonResult;
}

/// An extension reacting to an access token request with a provided access token.
pub trait AccessTokenAddon: GrantExtension {
    /// Process an access token request, utilizing the extensions stored data if any.
    ///
    /// The semantics are equivalent to that of `CodeExtension` except that any data which was
    /// returned as a response to the authorization code request is provided as an additional
    /// parameter.
    fn execute(&self, request: &dyn AccessTokenRequest, code_data: Option<Value>) -> AddonResult;
}

impl<'a, T: AuthorizationAddon + ?Sized> AuthorizationAddon for &'a T {
    fn execute(&self, request: &dyn AuthorizationRequest) -> AddonResult {
        (**self).execute(request)
    }
}

impl<'a, T: AuthorizationAddon + ?Sized> AuthorizationAddon for Cow<'a, T>
where
    T: Clone + ToOwned,
{
    fn execute(&self, request: &dyn AuthorizationRequest) -> AddonResult {
        self.as_ref().execute(request)
    }
}

impl<T: AuthorizationAddon + ?Sized> AuthorizationAddon for Box<T> {
    fn execute(&self, request: &dyn AuthorizationRequest) -> AddonResult {
        (**self).execute(request)
    }
}

impl<T: AuthorizationAddon + ?Sized> AuthorizationAddon for Arc<T> {
    fn execute(&self, request: &dyn AuthorizationRequest) -> AddonResult {
        (**self).execute(request)
    }
}

impl<T: AuthorizationAddon + ?Sized> AuthorizationAddon for Rc<T> {
    fn execute(&self, request: &dyn AuthorizationRequest) -> AddonResult {
        (**self).execute(request)
    }
}

impl<'a, T: AccessTokenAddon + ?Sized> AccessTokenAddon for &'a T {
    fn execute(&self, request: &dyn AccessTokenRequest, data: Option<Value>) -> AddonResult {
        (**self).execute(request, data)
    }
}

impl<'a, T: AccessTokenAddon + ?Sized> AccessTokenAddon for Cow<'a, T>
where
    T: Clone + ToOwned,
{
    fn execute(&self, request: &dyn AccessTokenRequest, data: Option<Value>) -> AddonResult {
        self.as_ref().execute(request, data)
    }
}

impl<T: AccessTokenAddon + ?Sized> AccessTokenAddon for Box<T> {
    fn execute(&self, request: &dyn AccessTokenRequest, data: Option<Value>) -> AddonResult {
        (**self).execute(request, data)
    }
}

impl<T: AccessTokenAddon + ?Sized> AccessTokenAddon for Arc<T> {
    fn execute(&self, request: &dyn AccessTokenRequest, data: Option<Value>) -> AddonResult {
        (**self).execute(request, data)
    }
}

impl<T: AccessTokenAddon + ?Sized> AccessTokenAddon for Rc<T> {
    fn execute(&self, request: &dyn AccessTokenRequest, data: Option<Value>) -> AddonResult {
        (**self).execute(request, data)
    }
}
