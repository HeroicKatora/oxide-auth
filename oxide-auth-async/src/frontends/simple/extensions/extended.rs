use oxide_auth::{
    frontends::simple::extensions::Extended,
    endpoint::{WebRequest, Scopes, Template, OAuthError},
};

use crate::{
    endpoint::{Endpoint, Extension, OwnerSolicitor},
    primitives::{Registrar, Authorizer, Issuer},
};

impl<Request, Inner, Ext> Endpoint<Request> for Extended<Inner, Ext>
where
    Request: WebRequest,
    Inner: Endpoint<Request>,
    Ext: Extension + Send,
{
    type Error = Inner::Error;

    fn registrar(&self) -> Option<&(dyn Registrar + Sync)> {
        self.inner.registrar()
    }

    fn authorizer_mut(&mut self) -> Option<&mut (dyn Authorizer + Send)> {
        self.inner.authorizer_mut()
    }

    fn issuer_mut(&mut self) -> Option<&mut (dyn Issuer + Send)> {
        self.inner.issuer_mut()
    }

    fn owner_solicitor(&mut self) -> Option<&mut (dyn OwnerSolicitor<Request> + Send)> {
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

    fn extension(&mut self) -> Option<&mut (dyn Extension + Send)> {
        Some(&mut self.addons)
    }
}
