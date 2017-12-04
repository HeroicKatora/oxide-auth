use super::{Url, Time};
use super::scope::Scope;
use std::borrow::Cow;

#[derive(Clone)]
pub struct Grant {
    pub owner_id: String,
    pub client_id: String,
    pub scope: Scope,
    pub redirect_url: Url,
    pub until: Time
}

pub struct GrantRef<'a> {
    pub owner_id: Cow<'a, str>,
    pub client_id: Cow<'a, str>,
    pub redirect_url: Cow<'a, Url>,
    pub scope: Cow<'a, Scope>,
    pub until: Cow<'a, Time>,
}

impl<'a> Into<GrantRef<'a>> for Grant {
    fn into(self) -> GrantRef<'a> {
        GrantRef {
            owner_id: Cow::Owned(self.owner_id),
            client_id: Cow::Owned(self.client_id),
            scope: Cow::Owned(self.scope),
            redirect_url: Cow::Owned(self.redirect_url),
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
            redirect_url: Cow::Borrowed(&self.redirect_url),
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
            redirect_url: self.redirect_url.into_owned(),
            until: self.until.into_owned()
        }
    }
}
