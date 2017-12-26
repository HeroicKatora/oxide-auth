//! Encapsulates various shared mechanisms for handlings different grants.

use super::{Url, Time};
use super::scope::Scope;
use std::borrow::Cow;

/// Owning copy of a grant.
///
/// This can be stored in a database without worrying about lifetimes or shared across thread
/// boundaries. A reference to this can be converted to a purely referential `GrantRef`.
#[derive(Clone)]
pub struct Grant {
    /// Identifies the owner of the resource.
    pub owner_id: String,

    /// Identifies the client to which the grant was issued.
    pub client_id: String,

    /// The scope granted to the client.
    pub scope: Scope,

    /// The redirection uri under which the client resides. The url package does indeed seem to
    /// parse valid URIs as well.
    pub redirect_uri: Url,

    /// Expiration date of the grant (Utc).
    pub until: Time
}

/// An optionally owning version of a grant.
///
/// Often used as an input or output type, this version enables zero-copy algorithms for several
/// primitives such as scope rewriting by a registrar or token generation. It can be converted to
/// a `Grant` if ownership is desired and necessary.
pub struct GrantRef<'a> {
    /// Identifies the owner of the resource.
    pub owner_id: Cow<'a, str>,

    /// Identifies the client to which the grant was issued.
    pub client_id: Cow<'a, str>,

    /// The scope granted to the client.
    pub scope: Cow<'a, Scope>,

    /// The redirection url under which the client resides.
    pub redirect_uri: Cow<'a, Url>,

    /// Expiration date of the grant (Utc).
    pub until: Cow<'a, Time>,
}

impl<'a> Into<GrantRef<'a>> for Grant {
    fn into(self) -> GrantRef<'a> {
        GrantRef {
            owner_id: Cow::Owned(self.owner_id),
            client_id: Cow::Owned(self.client_id),
            scope: Cow::Owned(self.scope),
            redirect_uri: Cow::Owned(self.redirect_uri),
            until: Cow::Owned(self.until),
        }
    }
}

impl<'a> Into<GrantRef<'a>> for &'a Grant {
    fn into(self) -> GrantRef<'a> {
        GrantRef {
            owner_id: Cow::Borrowed(&self.owner_id),
            client_id: Cow::Borrowed(&self.client_id),
            scope: Cow::Borrowed(&self.scope),
            redirect_uri: Cow::Borrowed(&self.redirect_uri),
            until: Cow::Borrowed(&self.until),
        }
    }
}

impl<'a> Into<Grant> for GrantRef<'a> {
    fn into(self) -> Grant {
        Grant {
            owner_id: self.owner_id.into_owned(),
            client_id: self.client_id.into_owned(),
            scope: self.scope.into_owned(),
            redirect_uri: self.redirect_uri.into_owned(),
            until: self.until.into_owned()
        }
    }
}

/// A non-owning grant request which does not yet have an expiration date attached.
pub struct GrantRequest<'a> {
    /// Identifies the owner of the resource.
    pub owner_id: &'a str,

    /// Identifies the client to which the grant should be issued.
    pub client_id: &'a str,

    /// The scope to be granted to the client.
    pub scope: &'a Scope,

    /// The redirection url under which the client resides.
    pub redirect_uri: &'a Url,
}
