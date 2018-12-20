/// Helper for ad-hoc authorization endpoints needs.
///
/// Does not own any of its data and implements `Endpoint` only in so far as to be compatible for
/// creating an `AuthorizationFlow` instance.
use primitives::authorizer::Authorizer;
use primitives::issuer::Issuer;
use primitives::registrar::Registrar;
use primitives::scope::Scope;

use code_grant::endpoint::{AccessTokenFlow, Endpoint, OwnerSolicitor, OAuthError, ResponseKind, WebRequest};

pub struct AccessToken<'a> {
    registrar: &'a Registrar,
    authorizer: &'a mut Authorizer,
    issuer: &'a mut Issuer,
}

#[derive(Debug)]
pub enum Error<W: WebRequest> {
    Web(W::Error),
    OAuth(OAuthError),
}

pub fn access_token_flow<'a, W>(registrar: &'a Registrar, authorizer: &'a mut Authorizer, issuer: &'a mut Issuer) 
    -> AccessTokenFlow<AccessToken<'a>, W>
    where W: WebRequest, W::Response: Default
{
    let flow = AccessTokenFlow::prepare(AccessToken {
        registrar,
        authorizer,
        issuer,
    });

    match flow {
        Err(_) => unreachable!(),
        Ok(flow) => flow,
    }
}

impl<'a, W> Endpoint<W> for AccessToken<'a> 
    where W: WebRequest, W::Response: Default
{
    type Error = Error<W>;

    fn registrar(&self) -> Option<&Registrar> {
        Some(self.registrar)
    }

    fn authorizer_mut(&mut self) -> Option<&mut Authorizer> {
        Some(self.authorizer)
    }

    fn issuer_mut(&mut self) -> Option<&mut Issuer> {
        Some(self.issuer)
    }

    fn owner_solicitor(&mut self) -> Option<&mut OwnerSolicitor<W>> {
        None
    }

    fn scopes(&mut self, _: &mut W) -> &[Scope] {
        const NO_SCOPES: [Scope; 0] = [];
        &NO_SCOPES[..]
    }

    fn response(&mut self, _: &mut W, _: ResponseKind) -> Result<W::Response, Self::Error> {
        Ok(W::Response::default())
    }

    fn error(&mut self, err: OAuthError) -> Error<W> {
        Error::OAuth(err)
    }

    fn web_error(&mut self, err: W::Error) -> Error<W> {
        Error::Web(err)
    }
}

