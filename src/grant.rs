use std::collections::HashSet;
extern crate chrono;
use self::chrono::DateTime;
use self::chrono::offset::Utc;

pub trait GrantLike {
    fn client_id(&self) -> &str;
    fn contains_scope(&self, &str) -> bool;
    fn until(&self) -> DateTime<Utc>;
}

pub struct SimpleGrant<'a> {
    client_id: &'a str,
    scope: HashSet<&'a str>,
    until: DateTime<Utc>
}

impl<'a> GrantLike for SimpleGrant<'a> {
    fn client_id(&self) -> &str {
        return self.client_id
    }

    fn contains_scope(&self, val: &str) -> bool {
        self.scope.contains(val)
    }

    fn until(&self) -> DateTime<Utc> {
        self.until
    }
}
