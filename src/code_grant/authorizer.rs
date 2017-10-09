use chrono::DateTime;
use chrono::Utc;

use iron::Url;
use std::collections::HashMap;

use super::{NegotiationParams, Negotiated, Authorizer, Request, AuthorizationParameters};

struct Data {
    default_scope: String,
    redirect_url: Url,
}

struct Grant {
    client_id: String,
    scope: String,
    until: DateTime<Utc>
}

pub struct Storage {
    clients: HashMap<String, Data>,
    tokens: HashMap<String, Grant>
}

impl Authorizer for Storage {
    fn negotiate(&self, params: NegotiationParams) -> Result<Negotiated, String> {
        match self.clients.get(params.client_id) {
            None => Err("Unregistered client".to_string()),
            Some(stored)
                if params.redirect_url.is_some() &&
                params.redirect_url.unwrap().as_ref() != stored.redirect_url.as_ref() => Err("Redirect url does not match".to_string()),
            Some(stored) => Ok(Negotiated {
                redirect_url: stored.redirect_url.clone(),
                scope: stored.default_scope.clone()
            })
        }
    }

    fn authorize(&mut self, req: &Request) -> String {
        req.client_id.to_string()
    }

    fn recover_parameters<'a>(&'a self, grant: &'a str) -> Option<AuthorizationParameters<'a>> {
        let grant = match self.tokens.get(grant) {
            None => return None,
            Some(v) => v
        };
        let client = self.clients.get(&grant.client_id).unwrap();
        Some(AuthorizationParameters {
            client_id: &grant.client_id,
            redirect_url: &client.redirect_url,
            scope: &grant.scope,
            until: &grant.until
        })
    }
}
