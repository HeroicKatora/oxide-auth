use std::collections::HashMap;
use std::borrow::Cow;
use chrono::{Duration, Utc};

use super::{Authorizer, Request, Grant, Time, TokenGenerator, Url};

struct SpecificGrant {
    owner_id: String,
    client_id: String,
    scope: String,
    redirect_url: Url,
    until: Time,
}

impl<'a> Into<Grant<'a>> for SpecificGrant {
    fn into(self) -> Grant<'a> {
        Grant {
            owner_id: Cow::Owned(self.owner_id),
            client_id: Cow::Owned(self.client_id),
            scope: Cow::Owned(self.scope),
            redirect_url: Cow::Owned(self.redirect_url),
            until: Cow::Owned(self.until),
        }
    }
}

impl<'a> Grant<'a> {
    fn from_refs(owner_id: &'a str, client_id: &'a str, scope: &'a str,
        redirect_url: &'a Url, until: &'a Time) -> Grant<'a> {
        Grant {
            owner_id: Cow::Borrowed(owner_id),
            client_id: Cow::Borrowed(client_id),
            scope: Cow::Borrowed(scope),
            redirect_url: Cow::Borrowed(redirect_url),
            until: Cow::Borrowed(until),
        }
    }
}

pub struct Storage<I: TokenGenerator> {
    issuer: I,
    tokens: HashMap<String, SpecificGrant>
}

impl<I: TokenGenerator> Storage<I> {
    pub fn new(issuer: I) -> Storage<I> {
        Storage {issuer: issuer, tokens: HashMap::new()}
    }
}

impl<I: TokenGenerator> Authorizer for Storage<I> {
    fn authorize(&mut self, req: Request) -> String {
        let owner_id = req.owner_id.to_string();
        let client_id = req.client_id.to_string();
        let scope = req.scope.to_string();
        let redirect_url = req.redirect_url.clone();
        let until = Utc::now() + Duration::minutes(10);

        let token = self.issuer.generate(
            &Grant::from_refs(&owner_id, &client_id, &scope, &redirect_url, &until));
        self.tokens.insert(token.clone(), SpecificGrant {
            owner_id, client_id, scope, redirect_url, until
        });
        token
    }

    fn extract<'a>(&mut self, grant: &'a str) -> Option<Grant<'a>> {
        self.tokens.remove(grant).map(|v| v.into())
    }
}
