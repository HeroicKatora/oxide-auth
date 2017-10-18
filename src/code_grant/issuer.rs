use std::collections::HashMap;
use std::clone::Clone;
use chrono::{Utc, Duration};
use super::{Issuer, Grant, Request, Time, TokenGenerator, Url};

#[derive(Clone)]
struct SpecificGrant {
    owner_id: String,
    client_id: String,
    scope: String,
    redirect_url: Url,
    until: Time
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

pub struct TokenMap<G: TokenGenerator> {
    generator: G,
    access: HashMap<String, SpecificGrant>,
    refresh: HashMap<String, SpecificGrant>,
}

impl<G: TokenGenerator> TokenMap<G> {
    pub fn new(generator: G) -> Self {
        Self {
            generator: generator,
            access: HashMap::new(),
            refresh: HashMap::new(),
        }
    }
}

impl<G: TokenGenerator> Issuer for TokenMap<G> {
    fn issue(&mut self, req: Request) -> (String, String) {
        let grant = SpecificGrant {
            owner_id: req.owner_id.to_string(),
            client_id: req.client_id.to_string(),
            scope: req.scope.to_string(),
            redirect_url: req.redirect_url.clone(),
            until: Utc::now() + Duration::hours(1),
        };
        let token: String = self.generator.generate((&grant).into());
        let refresh: String = self.generator.generate((&grant).into());
        self.access.insert(token.clone(), grant.clone());
        self.refresh.insert(refresh.clone(), grant);
        (token, refresh)
    }

    fn recover_token<'a>(&'a self, token: &'a str) -> Option<Grant<'a>> {
        self.access.get(token).map(|v| v.into())
    }

    fn recover_refresh<'a>(&'a self, token: &'a str) -> Option<Grant<'a>> {
        self.refresh.get(token).map(|v| v.into())
    }
}
