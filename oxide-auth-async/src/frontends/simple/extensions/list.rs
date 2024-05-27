use async_trait::async_trait;
use oxide_auth::code_grant::authorization::Request;
use oxide_auth::code_grant::accesstoken::Request as TokenRequest;
use oxide_auth::code_grant::client_credentials::Request as ClientCredentialsRequest;
use oxide_auth::frontends::simple::extensions::{AddonList, AddonResult};
use oxide_auth::primitives::grant::Extensions;

use crate::endpoint::Extension;
use crate::code_grant::access_token::{Extension as AccessTokenExtension};
use crate::code_grant::authorization::Extension as AuthorizationExtension;
use crate::code_grant::client_credentials::{Extension as ClientCredentialsExtension};

impl Extension for AddonList {
    fn authorization(&mut self) -> Option<&mut (dyn AuthorizationExtension + Send)> {
        Some(self)
    }

    fn access_token(&mut self) -> Option<&mut (dyn AccessTokenExtension + Send)> {
        Some(self)
    }

    fn client_credentials(&mut self) -> Option<&mut (dyn ClientCredentialsExtension + Send)> {
        Some(self)
    }
}

#[async_trait]
impl AuthorizationExtension for AddonList {
    async fn extend(&mut self, request: &(dyn Request + Sync)) -> std::result::Result<Extensions, ()> {
        let mut result_data = Extensions::new();

        for ext in self.authorization.iter() {
            let result = ext.execute(request);

            match result {
                AddonResult::Ok => (),
                AddonResult::Data(data) => result_data.set(ext, data),
                AddonResult::Err => return Err(()),
            }
        }

        Ok(result_data)
    }
}

#[async_trait]
impl AccessTokenExtension for AddonList {
    async fn extend(
        &mut self, request: &(dyn TokenRequest + Sync), mut data: Extensions,
    ) -> std::result::Result<Extensions, ()> {
        let mut result_data = Extensions::new();

        for ext in self.access_token.iter() {
            let ext_data = data.remove(ext);
            let result = ext.execute(request, ext_data);

            match result {
                AddonResult::Ok => (),
                AddonResult::Data(data) => result_data.set(ext, data),
                AddonResult::Err => return Err(()),
            }
        }

        Ok(result_data)
    }
}

#[async_trait]
impl ClientCredentialsExtension for AddonList {
    async fn extend(
        &mut self, request: &(dyn ClientCredentialsRequest + Sync),
    ) -> std::result::Result<Extensions, ()> {
        let mut result_data = Extensions::new();

        for ext in self.client_credentials.iter() {
            let result = ext.execute(request);

            match result {
                AddonResult::Ok => (),
                AddonResult::Data(data) => result_data.set(ext, data),
                AddonResult::Err => return Err(()),
            }
        }

        Ok(result_data)
    }
}
