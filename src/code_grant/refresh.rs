//! Retrieve a refreshed access token.
use std::borrow::Cow;
use std::result::Result as StdResult;

use code_grant::error::{AccessTokenError, AccessTokenErrorType};
use primitives::issuer::{IssuedToken, Issuer};
use primitives::grant::Grant;
use primitives::registrar::{Registrar, RegistrarError};

/// Required content of a refresh request.
///
/// See [Refreshing an Access Token] in the rfc.
///
/// [Refreshing an Access Token]: https://tools.ietf.org/html/rfc6749#section-6
pub trait Request {
    /// Received request might not be encoded correctly. This method gives implementors the chance
    /// to signal that a request was received but its encoding was generally malformed. If this is
    /// the case, then no other attribute will be queried. This method exists mainly to make
    /// frontends straightforward by not having them handle special cases for malformed requests.
    fn valid(&self) -> bool;

    /// The refresh token with which to refresh.
    fn refresh_token(&self) -> Option<Cow<str>>;

    /// Optionally specifies the requested scope
    fn scope(&self) -> Option<Cow<str>>;

    /// Valid requests have this set to "refresh_token"
    fn grant_type(&self) -> Option<Cow<str>>;

    /// User:password of a basic authorization header.
    fn authorization(&self) -> Option<(Cow<str>, Cow<[u8]>)>;

    /// The client_id, optional parameter for public clients.
    fn client_id(&self) -> Option<Cow<str>>;

    /// Retrieve an additional parameter used in an extension
    fn extension(&self, key: &str) -> Option<Cow<str>>;
}

pub trait Endpoint {
    /// Authenticate the requesting confidential client.
    fn registrar(&self) -> &dyn Registrar;

    /// Recover and test the provided refresh token then issue new tokens.
    fn issuer(&mut self) -> &mut dyn Issuer;
}

/// Represents a bearer token, optional refresh token and the associated scope for serialization.
pub struct RefreshedToken(IssuedToken, String);

/// Defines actions for the response to an access token request.
pub enum Error {
    /// The token did not represent a valid token.
    Invalid(ErrorDescription),

    /// The client did not properly authorize itself.
    Unauthorized(ErrorDescription, String),

    /// An underlying primitive operation did not complete successfully.
    ///
    /// This is expected to occur with some endpoints. See `PrimitiveError` for
    /// more details on when this is returned.
    Primitive,
}

/// Simple wrapper around RefreshError.
///
/// Enables addtional json functionality to generate a properly formatted response in the user of
/// this module.
pub struct ErrorDescription {
    error: AccessTokenError,
}

type Result<T> = std::result::Result<T, Error>;

/// Try to get a refreshed access token.
pub fn refresh(handler: &mut dyn Endpoint, request: &dyn Request)
    -> Result<RefreshedToken> 
{
    unimplemented!()
}
