use std::collections::HashMap;
use chrono::{Duration, Utc};

use super::{Authorizer, NegotiationParameter, Negotiated, Request, Grant, Time, TokenGenerator, Url};

struct Data {
    default_scope: String,
    redirect_url: Url,
}

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
    clients: HashMap<String, Data>,
    tokens: HashMap<String, SpecificGrant>
}

impl<I: TokenGenerator> Storage<I> {
    pub fn new(issuer: I) -> Storage<I> {
        Storage {issuer: issuer, clients: HashMap::new(), tokens: HashMap::new()}
    }

    pub fn register_client(&mut self, client_id: &str, redirect_url: Url) {
        self.clients.insert(client_id.to_string(), Data{default_scope: "default".to_string(), redirect_url: redirect_url});
    }
}

impl<I: TokenGenerator> Authorizer for Storage<I> {
    fn negotiate<'a>(&self, params: NegotiationParameter<'a>) -> Result<Negotiated<'a>, String> {
        let client = match self.clients.get(params.client_id.as_ref()) {
            None => return Err("Unregistered client".to_string()),
            Some(stored) => stored
        };
        match params.redirect_url {
            Some(url) => if *url.as_ref() != client.redirect_url {
                return Err("Redirect url does not match".to_string());
            },
            None => ()
        };
        Ok(Negotiated {
            client_id: params.client_id.clone(),
            redirect_url: client.redirect_url.clone(),
            scope: client.default_scope.clone().into()
        })
    }

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
