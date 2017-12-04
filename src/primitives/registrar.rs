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
use ring::{constant_time, digest};
use ring::error::Unspecified;

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

    /// Look up a client id.
    fn client(&self, client_id: &str) -> Option<&Client>;
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
    /// A public client with no authentication information
    Public,

    /// A confidential client who needs to be authenticated before communicating
    Confidential{ passdata: Vec<u8>, },
}

/// A very simple, in-memory hash map of client ids to Client entries.
pub struct ClientMap {
    clients: HashMap<String, Client>,
}

impl Client {
    /// Create a public client
    pub fn public(client_id: &str, redirect_url: Url, default_scope: Scope) -> Client {
        Client { client_id: client_id.to_string(), redirect_url, default_scope, client_type: ClientType::Public }
    }

    /// Create a confidential client
    pub fn confidential(client_id: &str, redirect_url: Url, default_scope: Scope, passphrase: &[u8]) -> Client {
        let passdata = SHA256Policy.store(client_id, passphrase);
        Client {
            client_id: client_id.to_string(),
            redirect_url,
            default_scope,
            client_type: ClientType::Confidential { passdata },
        }
    }

    /// Try to authenticate with the client and passphrase. This check will success if either the
    /// client is public and no passphrase was provided or if the client is confidential and the
    /// passphrase matches.
    pub fn check_authentication(&self, passphrase: Option<&[u8]>) -> Result<&Self, Unspecified> {
        match (passphrase, &self.client_type) {
            (None, &ClientType::Public) => Ok(self),
            (Some(provided), &ClientType::Confidential{ passdata: ref stored })
                => SHA256Policy.check(&self.client_id, provided, stored).map(|()| self),
            _ => return Err(Unspecified)
        }
    }
}

/// Determines how passphrases are stored and checked. Most likely you want to use Argon2
trait PasswordPolicy {
    /// Transform the passphrase so it can be stored in the confidential client
    fn store(&self, client_id: &str, passphrase: &[u8]) -> Vec<u8>;
    fn check(&self, client_id: &str, passphrase: &[u8], stored: &[u8]) -> Result<(), Unspecified>;
}

/// Hashes the passphrase, salting with the client id. This is not optimal for passwords and will
/// be replaced with argon2 in a future commit which also enables better configurability, such as
/// supplying a secret key to argon2. This will probably be combined with a slight rework of the
/// exact semantics of `Client` and `Client::check_authentication`.
#[deprecated(since="0.1.0-alpha.1", note="Should be replaced with argon2 as soon as possible")]
struct SHA256Policy;

#[allow(deprecated)]
impl PasswordPolicy for SHA256Policy {
    fn store(&self, client_id: &str, passphrase: &[u8]) -> Vec<u8> {
        let mut context = digest::Context::new(&digest::SHA256);
        context.update(client_id.as_bytes());
        context.update(passphrase);
        context.finish().as_ref().to_vec()
    }

    fn check(&self, client_id: &str, passphrase: &[u8], stored: &[u8]) -> Result<(), Unspecified> {
        let mut context = digest::Context::new(&digest::SHA256);
        context.update(client_id.as_bytes());
        context.update(passphrase);
        constant_time::verify_slices_are_equal(context.finish().as_ref(), stored)
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//                             Standard Implementations of Registrars                            //
///////////////////////////////////////////////////////////////////////////////////////////////////

impl ClientMap {
    pub fn new() -> ClientMap {
        ClientMap { clients: HashMap::new() }
    }

    /// Insert or update the client record.
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

    fn client(&self, client_id: &str) -> Option<&Client> {
        self.clients.get(client_id)
    }
}
