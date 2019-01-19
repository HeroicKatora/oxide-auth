use std::borrow::Borrow;
use std::sync::Arc;

use super::{AuthorizationAddon, AccessTokenAddon, AddonResult};
use code_grant::accesstoken::{Extension as AccessTokenExtension, Request};
use code_grant::authorization::{Extension as AuthorizationExtension, Request as AuthRequest};
use endpoint::Extension;
use primitives::grant::Extensions;

/// A simple list of loosly related authorization and access addons.
///
/// The owning representation of access extensions can be switched out to `Box<_>`, `Rc<_>` or
/// other types.
#[derive(Debug)]
pub struct AddonList<
    Authorization=Arc<AuthorizationAddon>,
    AccessToken=Arc<AccessTokenAddon>> 
{
    authorization: Vec<Authorization>,
    access_token: Vec<AccessToken>,
}

impl<Auth, Acc> AddonList<Auth, Acc> {
    /// Create an empty extension system.
    pub fn new() -> Self {
        AddonList {
            authorization: vec![],
            access_token: vec![],
        }
    }

    /// Collect the addons to form a system.
    pub fn from<I, K>(authorization_addons: I, access_addons: K) -> Self 
    where
        I: IntoIterator<Item=Auth>,
        K: IntoIterator<Item=Acc>,
    {
        AddonList {
            authorization: authorization_addons.into_iter().collect(),
            access_token: access_addons.into_iter().collect(),
        }
    }

    /// Add an authorization extension.
    pub fn authorization(&mut self, extension: Auth) {
        self.authorization.push(extension)
    }

    /// Add an access token extension.
    pub fn access_token(&mut self, extension: Acc) {
        self.access_token.push(extension)
    }
}

impl<Auth, Acc> Default for AddonList<Auth, Acc> {
    fn default() -> Self {
        AddonList::new()
    }
}

impl<Auth, Acc> Extension for AddonList<Auth, Acc>
where 
    Auth: AuthorizationAddon,
    Acc: AccessTokenAddon,
{
    fn authorization(&mut self) -> Option<&mut AuthorizationExtension> {
        Some(self)
    }

    fn access_token(&mut self) -> Option<&mut AccessTokenExtension> {
        Some(self)
    }
}

impl<Auth, Acc> AccessTokenExtension for AddonList<Auth, Acc>
where
    Acc: AccessTokenAddon,
{
    fn extend(&mut self, request: &Request, mut data: Extensions) -> std::result::Result<Extensions, ()> {
        let mut result_data = Extensions::new();

        for ext in self.access_token.iter() {
            let raw = ext.borrow();

            let ext_data = data.remove(&raw);            
            let result = raw.execute(request, ext_data);

            match result {
                AddonResult::Ok => (),
                AddonResult::Data(data) => result_data.set(&raw, data),
                AddonResult::Err => return Err(()),
            }
        }

        Ok(result_data)
    }
}

impl<Auth, Acc> AuthorizationExtension for AddonList<Auth, Acc>
where
    Auth: AuthorizationAddon,
{
    fn extend(&mut self, request: &AuthRequest) -> Result<Extensions, ()> {
        let mut result_data = Extensions::new();

        for ext in self.authorization.iter() {
            let raw = ext.borrow();
            let result = raw.execute(request);

            match result {
                AddonResult::Ok => (),
                AddonResult::Data(data) => result_data.set(&raw, data),
                AddonResult::Err => return Err(()),
            }
        }

        Ok(result_data)
    }
}
