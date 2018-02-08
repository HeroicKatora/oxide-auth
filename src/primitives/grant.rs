//! Encapsulates various shared mechanisms for handlings different grants.
use super::{Url, Time};
use super::scope::Scope;

use std::borrow::Cow;
use std::collections::HashMap;

/// Provides a name registry for extensions.
pub trait GrantExtension {
    /// An unique identifier distinguishing this extension type for parsing and storing.
    /// Obvious choices are the registered names as administered by IANA or private identifiers.
    fn identifier(&self) -> &'static str;
}

/// Wraps the data for an extension as a string with access restrictions.
///
/// This is a generic way for extensions to store their data in a universal, encoded form. It is
/// also able to indicate the intended readers for such an extension so that backends can ensure
/// that private extension data is properly encrypted even when present in a self-encoded access
/// token.
///
/// Some extensions have semantics where the presence alone is the stored data, so storing data
/// is optional and storing no data is distinct from not attaching any extension instance at all.
#[derive(Clone)]
pub enum Extension {
    /// An extension that the token owner is allowed to read and interpret.
    Public(Option<String>),

    /// Identifies an extenion whose content and/or existance MUST be kept secret.
    Private(Option<String>),

    // Content which is not saved on the server but initialized/interpreted from other sources.
    // foreign_content: String,
}

/// Links one or several `GrantExtension` instances to their respective data.
///
/// This also serves as a clean interface for both frontend and backend to reliably and
/// conveniently manipulate or query the stored data sets.
#[derive(Clone)]
pub struct Extensions {
    extensions: HashMap<String, Extension>,
}

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
    pub until: Time,

    /// Encoded extensions existing on this Grant
    pub extensions: Extensions,
}

/// An optionally owning version of a grant.
///
/// Often used as an input or output type, this version enables zero-copy algorithms for several
/// primitives such as scope rewriting by a registrar or token generation. It can be converted to
/// a `Grant` if ownership is desired and necessary.
///
/// Additionally, a `GrantRef` can be assembled from multiple independent inputs instead of
/// requiring them to be grouped in a single struct already. Should this turn out not to be useful
/// and simply requiring addtional maintenance, it might get removed in a future release.
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

    /// Encoded extensions existing on this Grant
    pub extensions: Cow<'a, Extensions>,
}

impl Grant {
    /// Create a Copy on Write reference of this grant without any instant copying.
    pub fn as_grantref(&self) -> GrantRef {
        self.into()
    }
}

impl<'a> Into<GrantRef<'a>> for Grant {
    fn into(self) -> GrantRef<'a> {
        GrantRef {
            owner_id: Cow::Owned(self.owner_id),
            client_id: Cow::Owned(self.client_id),
            scope: Cow::Owned(self.scope),
            redirect_uri: Cow::Owned(self.redirect_uri),
            until: Cow::Owned(self.until),
            extensions: Cow::Owned(self.extensions),
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
            extensions: Cow::Borrowed(&self.extensions),
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
            until: self.until.into_owned(),
            extensions: self.extensions.into_owned(),
        }
    }
}

impl Extension {
    /// Creates an extension whose presence and content can be unveiled by the token holder.
    ///
    /// Note that this is
    pub fn public(content: Option<String>) -> Extension {
        Extension::Public(content)
    }

    /// Creates an extension with secret content only visible for the server.
    ///
    /// Token issuers should take special care to protect the content and the identifier of such
    /// an extension from being interpreted or correlated by the token holder.
    pub fn private(content: Option<String>) -> Extension {
        Extension::Private(content)
    }

    /// Ensures that the extension stored was created as public, returns `Err` if it was not.
    pub fn as_public(self) -> Result<Option<String>, ()> {
        match self {
            Extension::Public(content) => Ok(content),
            _ => Err(())
        }
    }

    /// Ensures that the extension stored was created as private, returns `Err` if it was not.
    pub fn as_private(self) -> Result<Option<String>, ()> {
        match self {
            Extension::Private(content) => Ok(content),
            _ => Err(())
        }
    }
}

impl Extensions {
    /// Create a new extension store.
    pub fn new() -> Extensions {
        Extensions {
            extensions: HashMap::new(),
        }
    }

    /// Set the stored content for a `GrantExtension` instance.
    pub fn set(&mut self, extension: &GrantExtension, content: Extension) {
        self.extensions.insert(extension.identifier().to_string(), content);
    }

    /// Retrieve the stored data of an instance.
    ///
    /// This removes the data from the store to avoid possible mixups and to allow a copyless
    /// retrieval of bigger data strings.
    pub fn remove(&mut self, extension: &GrantExtension) -> Option<Extension> {
        self.extensions.remove(extension.identifier())
    }
}
