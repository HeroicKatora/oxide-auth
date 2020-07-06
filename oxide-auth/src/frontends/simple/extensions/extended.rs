use endpoint::{Endpoint, Extension, OAuthError, OwnerSolicitor, Scopes, Template, WebRequest};
use primitives::authorizer::Authorizer;
use primitives::issuer::Issuer;
use primitives::registrar::Registrar;

use super::AddonList;

/// An inner endpoint with simple extensions.
///
/// If the inner endpoint had any extension, it will simply never be provided to any flow and
/// overwritten. Therefore, this is mainly useful for other endpoints that did not implement
/// extensions by themselves such as `frontends::simple::endpoint::Generic`.
pub struct Extended<Inner, Extension> {
    inner: Inner,
    addons: Extension,
}

impl<Inner> Extended<Inner, AddonList> {
    /// Wrap an endpoint with a standard extension system.
    pub fn new(inner: Inner) -> Self {
        Extended {
            inner,
            addons: AddonList::default(),
        }
    }
}

impl<Inner, E> Extended<Inner, E> {
    /// Wrap an inner endpoint with a preconstructed extension instance.
    pub fn extend_with(inner: Inner, extension: E) -> Self {
        Extended {
            inner,
            addons: extension,
        }
    }

    /// A reference to the extension.
    pub fn extension(&self) -> &E {
        &self.addons
    }

    /// A mutable reference to the extension.
    pub fn extension_mut(&mut self) -> &mut E {
        &mut self.addons
    }
}

impl<Request, Inner, Ext> Endpoint<Request> for Extended<Inner, Ext>
where
    Request: WebRequest,
    Inner: Endpoint<Request>,
    Ext: Extension,
{
    type Error = Inner::Error;

    fn registrar(&self) -> Option<&dyn Registrar> {
        self.inner.registrar()
    }

    fn authorizer_mut(&mut self) -> Option<&mut dyn Authorizer> {
        self.inner.authorizer_mut()
    }

    fn issuer_mut(&mut self) -> Option<&mut dyn Issuer> {
        self.inner.issuer_mut()
    }

    fn owner_solicitor(&mut self) -> Option<&mut dyn OwnerSolicitor<Request>> {
        self.inner.owner_solicitor()
    }

    fn scopes(&mut self) -> Option<&mut dyn Scopes<Request>> {
        self.inner.scopes()
    }

    fn response(
        &mut self, request: &mut Request, kind: Template,
    ) -> Result<Request::Response, Self::Error> {
        self.inner.response(request, kind)
    }

    fn error(&mut self, err: OAuthError) -> Self::Error {
        self.inner.error(err)
    }

    fn web_error(&mut self, err: Request::Error) -> Self::Error {
        self.inner.web_error(err)
    }

    fn extension(&mut self) -> Option<&mut dyn Extension> {
        Some(&mut self.addons)
    }
}
