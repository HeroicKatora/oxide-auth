//! Encapsulates various shared mechanisms for handlings different grants.
use super::{Url, Time};
use super::scope::Scope;

use std::borrow::{Cow, ToOwned};
use std::collections::HashMap;
use std::collections::hash_map::Iter;
use std::rc::Rc;
use std::sync::Arc;

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
#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extensions {
    extensions: HashMap<String, Extension>,
}

/// Owning copy of a grant.
///
/// This can be stored in a database without worrying about lifetimes or shared across thread
/// boundaries. A reference to this can be converted to a purely referential `GrantRef`.
#[derive(Clone, Debug, PartialEq, Eq)]
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

impl Extension {
    /// Creates an extension whose presence and content can be unveiled by the token holder.
    ///
    /// Anyone in possession of the token corresponding to such a grant is potentially able to read
    /// the content of a public extension.
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

    /// Set content for an extension without a corresponding instance.
    pub fn set_raw(&mut self, identifier: String, content: Extension) {
        self.extensions.insert(identifier.to_string(), content);
    }

    /// Retrieve the stored data of an instance.
    ///
    /// This removes the data from the store to avoid possible mixups and to allow a copyless
    /// retrieval of bigger data strings.
    pub fn remove(&mut self, extension: &GrantExtension) -> Option<Extension> {
        self.extensions.remove(extension.identifier())
    }

    /// Iterate of the public extensions whose presence and content is not secret.
    pub fn iter_public(&self) -> PublicExtensions {
        PublicExtensions(self.extensions.iter())
    }

    /// Iterate of the private extensions whose presence and content must not be revealed.
    pub fn iter_private(&self) -> PublicExtensions {
        PublicExtensions(self.extensions.iter())
    }
}

/// An iterator over the public extensions of a grant.
pub struct PublicExtensions<'a>(Iter<'a, String, Extension>);

/// An iterator over the private extensions of a grant.
///
/// Implementations which acquire an instance should take special not to leak any secrets to
/// clients and third parties.
pub struct PrivateExtensions<'a>(Iter<'a, String, Extension>);

impl<'a> Iterator for PublicExtensions<'a> {
    type Item = (&'a str, Option<&'a str>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.0.next() {
                None => return None,
                Some((key, &Extension::Public(ref content)))
                    => return Some((key, content.as_ref().map(|st| st.as_str()))),
                _ => (),
            }
        }
    }
}

impl<'a> Iterator for PrivateExtensions<'a> {
    type Item = (&'a str, Option<&'a str>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.0.next() {
                None => return None,
                Some((key, &Extension::Private(ref content)))
                    => return Some((key, content.as_ref().map(|st| st.as_str()))),
                _ => (),
            }
        }
    }
}

impl<'a, T: GrantExtension + ?Sized> GrantExtension for &'a T {
    fn identifier(&self) -> &'static str {
        (**self).identifier()
    }
}

impl<'a, T: GrantExtension + ?Sized> GrantExtension for Cow<'a, T> 
    where T: Clone + ToOwned
{
    fn identifier(&self) -> &'static str {
        self.as_ref().identifier()
    }
}

impl<T: GrantExtension + ?Sized> GrantExtension for Box<T> {
    fn identifier(&self) -> &'static str {
        (**self).identifier()
    }
}

impl<T: GrantExtension + ?Sized> GrantExtension for Arc<T> {
    fn identifier(&self) -> &'static str {
        (**self).identifier()
    }
}

impl<T: GrantExtension + ?Sized> GrantExtension for Rc<T> {
    fn identifier(&self) -> &'static str {
        (**self).identifier()
    }
}
