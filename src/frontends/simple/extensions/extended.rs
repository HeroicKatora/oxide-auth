use endpoint::{Endpoint, OAuthError, OwnerSolicitor, Scopes, Template, WebRequest};
use primitives::authorizer::Authorizer;
use primitives::issuer::Issuer;
use primitives::registrar::Registrar;

use super::System;

/// An inner endpoint with simple extensions.
pub struct Extended<Inner, Addon> {
    inner: Inner,
    addon: Addon,
}

impl<Inner, Auth, Acc> Extended<Inner, System<Auth, Acc>> {
    /// Wrap an endpoint with a standard extension system.
    pub fn new(inner: Inner) -> Self {
        Extended {
            inner,
            addon: System::default(),
        }
    }
}

impl<Inner, A> Extended<Inner, A> {
    pub fn extend_with(inner: Inner, addon: A) -> Self {
        Extended {
            inner,
            addon,
        }
    }

    pub fn addon(&self) -> &A {
        &self.addon
    }

    pub fn addon_mut(&mut self) -> &mut A {
        &mut self.addon
    }
}

impl<Request, Inner, Auth, Acc> Endpoint<Request> for Extended<Inner, System<Auth, Acc>>
where
    Request: WebRequest,
    Inner: Endpoint<Request> 
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
}
