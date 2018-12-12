use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::hash::Hash;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::Arc;

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

/// Return a reference to value in a collection if it is the only one.
///
/// For example, a vector of string like types returns a reference to its first
/// element if there are no other, else it returns `None`.
///
/// If this were done with slices, that would require choosing a particular
/// value type of the underlying slice e.g. `[String]`.
pub unsafe trait UniqueValue {
    /// Borrow the unique value reference.
    fn get_unique(&self) -> Option<&str>;
}

unsafe impl<K, V> QueryParameter for HashMap<K, V>
where
    K: Borrow<str> + Eq + Hash,
    V: UniqueValue + Eq + Hash,
{
    fn unique_value(&self, key: &str) -> Option<Cow<str>> {
        self.get(key).and_then(V::get_unique).map(Cow::Borrowed)
    }

    fn normalize(&self) -> NormalizedParameter {
        let inner = self
            .iter()
            .filter_map(|(key, val)| {
                val.get_unique().map(|value| (
                    Cow::Owned(key.borrow().to_string()),
                    Cow::Owned(value.to_string())
                ))
            })
            .collect();

        NormalizedParameter {
            inner,
        }
    }
}

unsafe impl UniqueValue for str {
    fn get_unique(&self) -> Option<&str> {
        Some(self)
    }
}

unsafe impl UniqueValue for String {
    fn get_unique(&self) -> Option<&str> {
        Some(&self)
    }
}

unsafe impl<'a, V> UniqueValue for &'a V 
    where V: AsRef<str> + ?Sized
{
    fn get_unique(&self) -> Option<&str> {
        Some(self.as_ref())
    }
}

unsafe impl<'a> UniqueValue for Cow<'a, str> {
    fn get_unique(&self) -> Option<&str> {
        Some(self.as_ref())
    }
}

unsafe impl<V: UniqueValue> UniqueValue for [V] {
    fn get_unique(&self) -> Option<&str> {
        if self.len() > 1 {
            None
        } else {
            self.get(0).and_then(V::get_unique)
        }
    }
}

unsafe impl<V: UniqueValue + ?Sized> UniqueValue for Box<V> {
    fn get_unique(&self) -> Option<&str> {
        (**self).get_unique()
    }
}

unsafe impl<V: UniqueValue + ?Sized> UniqueValue for Rc<V> {
    fn get_unique(&self) -> Option<&str> {
        (**self).get_unique()
    }
}

unsafe impl<V: UniqueValue + ?Sized> UniqueValue for Arc<V> {
    fn get_unique(&self) -> Option<&str> {
        (**self).get_unique()
    }
}

unsafe impl<V: UniqueValue> UniqueValue for Vec<V> {
    fn get_unique(&self) -> Option<&str> {
        if self.len() > 1 {
            None
        } else {
            self.get(0).and_then(V::get_unique)
        }
    }
}

mod test {
    use super::*;

    /// Compilation tests for various possible QueryParameter impls.
    #[allow(unused)]
    #[allow(dead_code)]
    fn test_query_parameter_impls() {
        let _ = (&HashMap::<String, String>::new()) as &QueryParameter;
        let _ = (&HashMap::<&'static str, &'static str>::new()) as &QueryParameter;
        let _ = (&HashMap::<Cow<'static, str>, Cow<'static, str>>::new()) as &QueryParameter;

        let _ = (&HashMap::<String, Vec<String>>::new()) as &QueryParameter;
        let _ = (&HashMap::<String, Box<String>>::new()) as &QueryParameter;
        let _ = (&HashMap::<String, Box<[Cow<'static, str>]>>::new()) as &QueryParameter;
    }
}
