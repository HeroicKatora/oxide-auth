use std::borrow::{Borrow, Cow};
use std::collections::HashMap;

/// Allows access to the query parameters in an url or a body.
///
/// Use one of the listed implementations below.
///
/// You should generally not have to implement this trait yourself, and if you do there are
/// additional requirements on your implementation to guarantee standard conformance. Therefore the
/// trait is marked as `unsafe`.
pub unsafe trait QueryParameter {
    /// Get the **unique** value associated with a key.
    ///
    /// If there are multiple values, return `None`. This is very important to guarantee
    /// conformance to the RFC. Afaik it prevents potentially subverting validation middleware,
    /// order dependent processing, or simple confusion between different components who parse the
    /// query string from different ends.
    fn unique_value(&self, key: &str) -> Option<Cow<str>>;

    /// Guarantees that one can grab an owned copy.
    fn normalize(&self) -> NormalizedParameter;
}

/// The query parameter normal form.
///
/// When a request wants to give access to its query or body parameters by reference, it can do so
/// by a reference of the particular trait. But when the representation of the query is not stored
/// in the memory associated with the request, it needs to be allocated to outlive the borrow on
/// the request.  This allocation may as well perform the minimization/normalization into a
/// representation actually consumed by the backend. This normal form thus encapsulates the
/// associated `clone-into-normal form` by various possible constructors from references [WIP].
///
/// This gives rise to a custom `Cow<QueryParameter>` instance by requiring that normalization into
/// memory with unrelated lifetime is always possible.
///
/// Internally a hashmap but this may change due to optimizations.
#[derive(Clone, Debug, Default)]
pub struct NormalizedParameter {
    inner: HashMap<Cow<'static, str>, Cow<'static, str>>,
}

unsafe impl QueryParameter for NormalizedParameter {
    fn unique_value(&self, key: &str) -> Option<Cow<str>> {
        self.inner.get(key).cloned()
    }

    fn normalize(&self) -> NormalizedParameter {
        self.clone()
    }
}

impl Borrow<QueryParameter> for NormalizedParameter {
    fn borrow(&self) -> &(QueryParameter + 'static) {
        self
    }
}

impl ToOwned for QueryParameter {
    type Owned = NormalizedParameter;

    fn to_owned(&self) -> Self::Owned {
        self.normalize()
    }
}

unsafe impl QueryParameter for HashMap<String, String> {
    fn unique_value(&self, key: &str) -> Option<Cow<str>> {
        self.get(key).cloned().map(Cow::Owned)
    }

    fn normalize(&self) -> NormalizedParameter {
        let inner = self.iter()
            .map(|(key, val)| (Cow::Owned(key.to_string()), Cow::Owned(val.to_string())))
            .collect();

        NormalizedParameter {
            inner,
        }
    }
}
