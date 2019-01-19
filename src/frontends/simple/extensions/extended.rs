use endpoint::{Endpoint, Extension, OAuthError, OwnerSolicitor, Scopes, Template, WebRequest};
use primitives::authorizer::Authorizer;
use primitives::issuer::Issuer;
use primitives::registrar::Registrar;

use super::{AuthorizationAddon, AccessTokenAddon, AddonList};

/// An inner endpoint with simple extensions.
pub struct Extended<Inner, Extension> {
    inner: Inner,
    addons: Extension,
}

impl<Inner, Auth, Acc> Extended<Inner, AddonList<Auth, Acc>> {
    /// Wrap an endpoint with a standard extension system.
    pub fn new(inner: Inner) -> Self {
        Extended {
            inner,
            addons: AddonList::default(),
        }
    }
}

impl<Inner, E> Extended<Inner, E> {
    pub fn extend_with(inner: Inner, extension: E) -> Self {
        Extended {
            inner,
            addons: extension,
        }
    }

    pub fn extension(&self) -> &E {
        &self.addons
    }

    pub fn extension_mut(&mut self) -> &mut E {
        &mut self.addons
    }
}

impl<Request, Inner, Auth, Acc> Endpoint<Request> for Extended<Inner, AddonList<Auth, Acc>>
where
    Request: WebRequest,
    Inner: Endpoint<Request>,
    Auth: AuthorizationAddon,
    Acc: AccessTokenAddon,
{
    type Error = Inner::Error;

    fn registrar(&self) -> Option<&Registrar> {
        self.inner.registrar()
    }

    fn authorizer_mut(&mut self) -> Option<&mut Authorizer> {
        self.inner.authorizer_mut()
    }

    fn issuer_mut(&mut self) -> Option<&mut Issuer> {
        self.inner.issuer_mut()
    }

    fn owner_solicitor(&mut self) -> Option<&mut OwnerSolicitor<Request>> {
        self.inner.owner_solicitor()
    }

    fn scopes(&mut self) -> Option<&mut Scopes<Request>> {
        self.inner.scopes()
    }

    fn response(&mut self, request: &mut Request, kind: Template)
        -> Result<Request::Response, Self::Error>
    {
        self.inner.response(request, kind)
    }

    fn error(&mut self, err: OAuthError) -> Self::Error {
        self.inner.error(err)
    }

    fn web_error(&mut self, err: Request::Error) -> Self::Error {
        self.inner.web_error(err)
    }

    fn extension(&mut self) -> Option<&mut Extension> {
        Some(&mut self.addons)
    }
}
