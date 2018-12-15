use std::borrow::Borrow;
use std::sync::Arc;

use super::{AuthorizationExtension, AccessTokenExtension, ExtensionResult};
use code_grant::accesstoken::{ExtensionSystem, Request};
use primitives::grant::{Extensions};

/// A simple system providing extensions to authorization and access token requests.
///
/// This extension system is suitable to group mostly unrelated extensions together.
///
/// The owning representation of access extensions can be switched out to `Box<_>`, `Rc<_>` or
/// other types.
#[derive(Debug, Default)]
pub struct System<
    Authorization=Arc<AuthorizationExtension>,
    AccessToken=Arc<AccessTokenExtension>
> {
    authorization: Vec<Authorization>,
    access_token: Vec<AccessToken>,
}

impl<Auth, Acc> System<Auth, Acc> {
    /// Create an empty extension system.
    pub fn new() {
        Default::default()
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

impl<Auth, Acc> ExtensionSystem for System<Auth, Acc>
    where Acc: AccessTokenExtension
{
    fn extend(&self, request: &Request, mut data: Extensions) -> std::result::Result<Extensions, ()> {
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
