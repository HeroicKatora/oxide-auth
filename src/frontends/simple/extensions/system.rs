use std::borrow::Borrow;
use std::sync::Arc;

use super::{
    AuthorizationExtension as AuthorizationAddon,
    AccessTokenExtension as AccessTokenAddon,
    ExtensionResult};
use code_grant::accesstoken::{Extension as AccessTokenExtension, Request};
use code_grant::authorization::{Extension as AuthorizationExtension, Request as AuthRequest};
use primitives::grant::Extensions;

/// A simple system providing extensions to authorization and access token requests.
///
/// This extension system is suitable to group mostly unrelated extensions together.
///
/// The owning representation of access extensions can be switched out to `Box<_>`, `Rc<_>` or
/// other types.
#[derive(Debug)]
pub struct System<
    Authorization=Arc<AuthorizationAddon>,
    AccessToken=Arc<AccessTokenAddon>> 
{
    authorization: Vec<Authorization>,
    access_token: Vec<AccessToken>,
}

impl<Auth, Acc> System<Auth, Acc> {
    /// Create an empty extension system.
    pub fn new() -> Self {
        System {
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
        System {
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

impl<Auth, Acc> Default for System<Auth, Acc> {
    fn default() -> Self {
        System::new()
    }
}

impl<Auth, Acc> AccessTokenExtension for System<Auth, Acc>
where
    Acc: AccessTokenAddon,
{
    fn extend(&mut self, request: &Request, mut data: Extensions) -> std::result::Result<Extensions, ()> {
        let mut result_data = Extensions::new();

        for ext in self.access_token.iter() {
            let raw = ext.borrow();

            let ext_data = data.remove(&raw);            
            let result = raw.extend_access_token(request, ext_data);

            match result {
                ExtensionResult::Ok => (),
                ExtensionResult::Data(data) => result_data.set(&raw, data),
                ExtensionResult::Err => return Err(()),
            }
        }

        Ok(result_data)
    }
}

impl<Auth, Acc> AuthorizationExtension for System<Auth, Acc>
where
    Auth: AuthorizationAddon,
{
    fn extend(&mut self, request: &AuthRequest) -> Result<Extensions, ()> {
        let mut result_data = Extensions::new();

        for ext in self.authorization.iter() {
            let raw = ext.borrow();
            let result = raw.extend_code(request);

            match result {
                ExtensionResult::Ok => (),
                ExtensionResult::Data(data) => result_data.set(&raw, data),
                ExtensionResult::Err => return Err(()),
            }
        }

        Ok(result_data)
    }
}
