use std::collections::HashMap;
use chrono::{Duration, Utc};

use super::{Authorizer, Request, Grant, Time, TokenGenerator, Url};

struct SpecificGrant {
    owner_id: String,
    client_id: String,
    scope: String,
    redirect_url: Url,
    until: Time,
}

impl<'a> Into<Grant<'a>> for &'a SpecificGrant {
    fn into(self) -> Grant<'a> {
        Grant {
            owner_id: &self.owner_id,
            client_id: &self.client_id,
            scope: &self.scope,
            redirect_url: &self.redirect_url,
            until: &self.until,
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
        let grant = SpecificGrant{
                owner_id: req.owner_id.to_string(),
                client_id: req.client_id.to_string(),
                scope: req.scope.to_string(),
                redirect_url: req.redirect_url.clone(),
                until: Utc::now() + Duration::minutes(10)};
        let token = self.issuer.generate((&grant).into());
        self.tokens.insert(token.clone(), grant);
        token
    }

    fn recover_parameters<'a>(&'a self, grant: &'a str) -> Option<Grant<'a>> {
        self.tokens.get(grant).map(|v| v.into())
    }
}
