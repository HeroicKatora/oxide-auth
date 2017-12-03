//! Registrars administer a database of known clients.
//!
//! It will govern their redirect urls and allowed scopes to request tokens for. When an oauth
//! request turns up, it is the registrars duty to verify the requested scope and redirect url for
//! consistency in the permissions granted and urls registered.
//!
//! For confidential clients [WIP], it is also responsible for authentication verification.
use super::{NegotiationParameter, Scope};
use std::borrow::Cow;
use std::collections::HashMap;
use url::Url;

/// Registrars provie a way to interact with clients.
///
/// Most importantly, they determine defaulted parameters for a request as well as the validity
/// of provided parameters. In general, implementations of this trait will probably offer an
/// interface for registering new clients. This interface is not covered by this library.
pub trait Registrar {
    /// Determine the allowed scope and redirection url for the client. The registrar may override
    /// the scope entirely or simply substitute a default scope in case none is given. Redirection
    /// urls should be matched verbatim, not partially.
    fn negotiate<'a>(&self, NegotiationParameter<'a>) -> Result<Cow<'a, Scope>, RegistrarError>;

    /// Return the authenticated client if authentication with the provided passphrase succeeded.
    /// In case the client is not a confidential client, fail as well.
    fn authenticate(&self, client_id: &str, passphrase: &str) -> Result<&Client, ()>;
}

pub enum RegistrarError {
    Unregistered,
    MismatchedRedirect,
    UnauthorizedClient,
}

pub struct Client {
    client_id: String,
    redirect_url: Url,
    default_scope: Scope,
    client_type: ClientType,
}

enum ClientType {
    Public,
    Confidential{ passphrase: String, },
}

pub struct ClientMap {
    clients: HashMap<String, Client>,
}

impl Client {
    /// Create a public client
    pub fn public(client_id: &str, redirect_url: Url, default_scope: Scope) -> Client {
        Client { client_id: client_id.to_string(), redirect_url, default_scope, client_type: ClientType::Public }
    }

    /// Create a confidential client
    pub fn confidential(client_id: &str, redirect_url: Url, default_scope: Scope, passphrase: &str) -> Client {
        Client {
            client_id: client_id.to_string(),
            redirect_url,
            default_scope,
            client_type: ClientType::Confidential { passphrase: passphrase.to_string() },
        }
    }

    /// Ok only if this client is confidential and the passphrase matches
    pub fn authenticate(&self, passphrase: &str) -> Result<(), ()> {
        let secret = match self.client_type {
            ClientType::Confidential{ ref passphrase } => passphrase,
            _ => return Err(())
        };
        Err(())
    }
}

impl ClientMap {
    pub fn new() -> ClientMap {
        ClientMap { clients: HashMap::new() }
    }

    pub fn register_client(&mut self, client: Client) {
        self.clients.insert(client.client_id.clone(), client);
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

    fn authenticate(&self, client_id: &str, passphrase: &str) -> Result<&Client, ()> {
        let client = self.clients.get(client_id).ok_or(())?;
        client.authenticate(passphrase)?;
        Ok(client)
    }
}
