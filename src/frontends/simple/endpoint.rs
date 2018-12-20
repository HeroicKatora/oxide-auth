/// Helper for ad-hoc authorization endpoints needs.
///
/// Does not own any of its data and implements `Endpoint` only in so far as to be compatible for
/// creating an `AuthorizationFlow` instance.
use primitives::authorizer::Authorizer;
use primitives::issuer::Issuer;
use primitives::registrar::Registrar;
use primitives::scope::Scope;

use code_grant::endpoint::{AuthorizationFlow, Endpoint, OAuthError, WebRequest};

pub struct Authorization<'a> {
    registrar: &'a Registrar,
    authorizer: &'a mut Authorizer,
}

pub enum Error<W: WebRequest> {
    Web(W::Error),
    OAuth(OAuthError),
}

impl<'a> Authorization<'a> {
    pub fn authorization_flow<W>() -> AuthorizationFlow<Self, W>
        where W: WebRequest, W::Response: Default
    {
    }
}

impl<'a, W> Endpoint<W> for Authorization<'a> 
    where W: WebRequest, W::Response: Default
{
    type Error = Error<W>;
}

impl<W: WebRequest> From<W::Error> for Error<W> {
    fn from(err: W::Error) -> Self {
        Error::Web(err)
    }
}
