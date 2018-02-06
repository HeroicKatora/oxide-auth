use super::backend::{AccessTokenRequest, CodeRequest};
use primitives::grant::{Extension, GrantExtension};

pub trait CodeExtension: GrantExtension {
    fn extend(&self, &CodeRequest) -> Result<Option<Extension>, ()>;
}

pub trait AccessTokenExtension: GrantExtension {
    fn extend(&self, &AccessTokenRequest, Option<Extension>)
        -> Result<Option<Extension>, ()>;
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

mod pkce;

pub use self::pkce::Pkce;
