//! Registrars administer a database of known clients.
//!
//! It will govern their redirect urls and allowed scopes to request tokens for. When an oauth
//! request turns up, it is the registrars duty to verify the requested scope and redirect url for
//! consistency in the permissions granted and urls registered.
//! 
//! For confidential clients [WIP], it is also responsible for authentication verification.
use super::{Registrar, NegotiationParameter, RegistrarError, Scope};
use std::borrow::Cow;
use std::collections::HashMap;
use url::Url;

struct Data {
    default_scope: Scope,
    redirect_url: Url,
}

pub struct ClientMap {
    clients: HashMap<String, Data>,
}

impl ClientMap {
    pub fn new() -> ClientMap {
        ClientMap { clients: HashMap::new() }
    }

    pub fn register_client(&mut self, client_id: &str, redirect_url: Url) {
        self.clients.insert(client_id.to_string(),
            Data{ default_scope: "default".parse().unwrap(), redirect_url: redirect_url});
    }
}

impl Registrar for ClientMap {
    fn negotiate<'a>(&self, params: NegotiationParameter<'a>) -> Result<Cow<'a, Scope>, RegistrarError> {
        let client = match self.clients.get(params.client_id.as_ref()) {
            None => return Err(RegistrarError::Unregistered),
            Some(stored) => stored
        };
        // Perform exact matching as motivated in the rfc
        if *params.redirect_url.as_ref() != client.redirect_url {
            return Err(RegistrarError::MismatchedRedirect);
        }
        // Don't allow any scope deviation from the default
        Ok(Cow::Owned(client.default_scope.clone()))
    }
}
