use std::borrow::Borrow;

use super::{AuthorizationExtension, AccessTokenExtension, ExtensionResult};
use code_grant_2::accesstoken::{ExtensionSystem, Request};
use primitives::grant::{Extensions};

/// A simple system providing extensions to authorization and access token requests.
///
/// The owning representation of access extensions can be switched out to `Arc<_>`, `Rc<_>` or other types.
pub struct System<
    AuthorizationContainer=Box<AuthorizationExtension>,
    AccessTokenContainer=Box<AccessTokenExtension>
> {
    authorization: Vec<AuthorizationContainer>,
    access_token: Vec<AccessTokenContainer>,
}

impl<Auth, Acc> ExtensionSystem for System<Auth, Acc>
    where Acc: Borrow<AccessTokenExtension>
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
