use std::fmt;
use std::sync::Arc;

use super::{AuthorizationAddon, AccessTokenAddon, AddonResult};
use code_grant::accesstoken::{Extension as AccessTokenExtension, Request};
use code_grant::authorization::{Extension as AuthorizationExtension, Request as AuthRequest};
use endpoint::Extension;
use primitives::grant::{Extensions, GrantExtension};

/// A simple list of loosly related authorization and access addons.
///
/// The owning representation of access extensions can be switched out to `Box<_>`, `Rc<_>` or
/// other types.
pub struct AddonList {
    authorization: Vec<Arc<dyn AuthorizationAddon + Send + Sync + 'static>>,
    access_token: Vec<Arc<dyn AccessTokenAddon + Send + Sync + 'static>>,
}

impl AddonList {
    /// Create an empty extension system.
    pub fn new() -> Self {
        AddonList {
            authorization: vec![],
            access_token: vec![],
        }
    }

    /// Add an addon that only applies to authorization.
    pub fn push_authorization<A>(&mut self, addon: A)
    where
        A: AuthorizationAddon + Send + Sync + 'static,
    {
        self.authorization.push(Arc::new(addon))
    }

    /// Add an addon that only applies to access_token.
    pub fn push_access_token<A>(&mut self, addon: A)
    where
        A: AccessTokenAddon + Send + Sync + 'static,
    {
        self.access_token.push(Arc::new(addon))
    }

    /// Add an addon that applies to the whole code grant flow.
    ///
    /// The addon gets added both the authorization and access token addons.
    pub fn push_code<A>(&mut self, addon: A)
    where
        A: AuthorizationAddon + AccessTokenAddon + Send + Sync + 'static,
    {
        let arc = Arc::new(addon);
        self.authorization.push(arc.clone());
        self.access_token.push(arc)
    }
}

impl Default for AddonList {
    fn default() -> Self {
        AddonList::new()
    }
}

impl Extension for AddonList {
    fn authorization(&mut self) -> Option<&mut dyn AuthorizationExtension> {
        Some(self)
    }

    fn access_token(&mut self) -> Option<&mut dyn AccessTokenExtension> {
        Some(self)
    }
}

impl AccessTokenExtension for AddonList {
    fn extend(
        &mut self, request: &dyn Request, mut data: Extensions,
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

impl AuthorizationExtension for AddonList {
    fn extend(&mut self, request: &dyn AuthRequest) -> Result<Extensions, ()> {
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

impl fmt::Debug for AddonList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::slice::Iter;
        struct ExtIter<'a, T: GrantExtension + 'a>(Iter<'a, T>);

        impl<'a, T: GrantExtension> fmt::Debug for ExtIter<'a, T> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.debug_list().entries(self.0.clone().map(T::identifier)).finish()
            }
        }

        f.debug_struct("AddonList")
            .field("authorization", &ExtIter(self.authorization.iter()))
            .field("access_token", &ExtIter(self.access_token.iter()))
            .finish()
    }
}
