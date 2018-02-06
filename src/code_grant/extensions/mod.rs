use super::backend::{AccessTokenRequest, CodeRequest};
use primitives::grant::{Extension, Grant, GrantExtension};

pub trait CodeExtension: GrantExtension {
    fn initialize(&self, &CodeRequest) -> Result<Option<Extension>, ()>;
}

pub trait AccessTokenExtension: GrantExtension {
    fn initialize(&self, &AccessTokenRequest, &Grant) -> Result<Option<Extension>, ()>;
}

impl<'a> GrantExtension for &'a CodeExtension {
    fn identifier(&self) -> &'static str {
        (*self).identifier()
    }
}

impl<'a> GrantExtension for &'a AccessTokenExtension {
    fn identifier(&self) -> &'static str {
        (*self).identifier()
    }
}
