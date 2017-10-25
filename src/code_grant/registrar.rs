use super::{Registrar, NegotiationParameter, Negotiated};
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
}
