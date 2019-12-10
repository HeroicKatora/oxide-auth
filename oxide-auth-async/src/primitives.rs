//! Async versions of all primitives traits.
use async_trait::async_trait;
use oxide_auth::primitives::{grant::Grant, scope::Scope};
use oxide_auth::primitives::issuer::{IssuedToken, RefreshedToken};
use oxide_auth::primitives::registrar::{ClientUrl, BoundClient, RegistrarError, PreGrant};

#[async_trait(?Send)]
pub trait Issuer {
    async fn issue(&mut self, _: Grant) -> Result<IssuedToken, ()>;

    async fn refresh(&mut self, _: &str, _: Grant) -> Result<RefreshedToken, ()>;

    async fn recover_token(&mut self, _: &str) -> Result<Option<Grant>, ()>;

    async fn recover_refresh(&mut self, _: &str) -> Result<Option<Grant>, ()>;
}

#[async_trait(?Send)]
impl<T> Issuer for T
    where T: oxide_auth::primitives::issuer::Issuer + ?Sized,
{
    async fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        oxide_auth::primitives::issuer::Issuer::issue(self, grant)
    }

    async fn refresh(&mut self, token: &str, grant: Grant) -> Result<RefreshedToken, ()> {
        oxide_auth::primitives::issuer::Issuer::refresh(self, token, grant)
    }

    async fn recover_token(&mut self, token: &str) -> Result<Option<Grant>, ()> {
        oxide_auth::primitives::issuer::Issuer::recover_token(self, token)
    }

    async fn recover_refresh(&mut self, token: &str) -> Result<Option<Grant>, ()> {
        oxide_auth::primitives::issuer::Issuer::recover_refresh(self, token)
    }
}

#[async_trait(?Send)]
pub trait Registrar {
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>)
        -> Result<BoundClient<'a>, RegistrarError>;

    async fn negotiate<'a>(&self, client: BoundClient<'a>, scope: Option<Scope>)
        -> Result<PreGrant, RegistrarError>;

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>)
        -> Result<(), RegistrarError>;
}

#[async_trait(?Send)]
impl<T> Registrar for T
    where T: oxide_auth::primitives::registrar::Registrar + ?Sized,
{
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>)
        -> Result<BoundClient<'a>, RegistrarError>
    {
        oxide_auth::primitives::registrar::Registrar::bound_redirect(self, bound)
    }

    async fn negotiate<'a>(&self, client: BoundClient<'a>, scope: Option<Scope>)
        -> Result<PreGrant, RegistrarError>
    {
        oxide_auth::primitives::registrar::Registrar::negotiate(self, client, scope)
    }

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>)
        -> Result<(), RegistrarError>
    {
        oxide_auth::primitives::registrar::Registrar::check(self, client_id, passphrase)
    }
}
