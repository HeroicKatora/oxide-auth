pub use code_grant_2::authorization::Request as AuthorizationRequest;
pub use code_grant_2::accesstoken::Request as AccessTokenRequest;

mod system;

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
