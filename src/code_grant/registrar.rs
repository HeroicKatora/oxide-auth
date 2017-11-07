use super::{Registrar, NegotiationParameter, RegistrarError};
use std::borrow::Cow;
use std::collections::HashMap;
use url::Url;

struct Data {
    default_scope: String,
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
        self.clients.insert(client_id.to_string(), Data{default_scope: "default".to_string(), redirect_url: redirect_url});
    }
}

impl Registrar for ClientMap {
    fn negotiate<'a>(&self, params: NegotiationParameter<'a>) -> Result<Cow<'a, str>, RegistrarError> {
        let client = match self.clients.get(params.client_id.as_ref()) {
            None => return Err(RegistrarError::Unregistered),
            Some(stored) => stored
        };
        // Perform exact matching as motivated in the rfc
        if *params.redirect_url.as_ref() != client.redirect_url {
            return Err(RegistrarError::MismatchedRedirect);
        }
        // Don't allow any scope deviation from the default
        Ok(client.default_scope.clone().into())
    }
}
