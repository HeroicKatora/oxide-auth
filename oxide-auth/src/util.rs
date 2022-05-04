use std::borrow::Cow;

// avoids allocation on `Cow::Owned`.
pub fn avoid_alloc_cow_str_to_string(cow: Cow<str>) -> String {
    match cow {
        Cow::Borrowed(b) => b.to_string(),
        Cow::Owned(o) => o,
    }
}
