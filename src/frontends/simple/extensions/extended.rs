use endpoint::{Endpoint, OAuthError, OwnerSolicitor, Scopes, Template, WebRequest};
use primitives::authorizer::Authorizer;
use primitives::issuer::Issuer;
use primitives::registrar::Registrar;

use super::System;

/// An inner endpoint with simple extensions.
pub struct Extended<Inner, System> {
    inner: Inner,
    system: System,
}

impl<Inner> Extended<Inner> {
    pub fn new(inner: Inner) -> Self {
        Extended {
            inner,
            system: System::new(),
        }
    }

    pub fn system_mut(&mut self) -> &mut System {
        &mut self.system
    }
}

impl<Request, Inner> Endpoint<Request> for Extended<Inner>
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
