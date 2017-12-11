//! Registrars administer a database of known clients.
//!
//! It will govern their redirect urls and allowed scopes to request tokens for. When an oauth
//! request turns up, it is the registrars duty to verify the requested scope and redirect url for
//! consistency in the permissions granted and urls registered.
use super::scope::Scope;
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
    fn bound_redirect<'a>(&'a self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError>;

    /// Look up a client id.
    fn client(&self, client_id: &str) -> Option<&Client>;
}

pub struct ClientUrl<'a> {
    pub client_id: Cow<'a, str>,
    pub redirect_url: Option<Cow<'a, Url>>,
}

pub struct BoundClient<'a> {
    pub client_id: Cow<'a, str>,
    pub redirect_url: Cow<'a, Url>,
    pub client: &'a Client,
}

/// These are the parameters presented to the resource owner when confirming or denying a grant
/// request. Together with the owner_id and a computed expiration time stamp, this will form a
/// grant of some sort. In the case of the authorization code grant flow, it will be an
/// authorization code at first, which can be traded for an access code by the client acknowledged.
pub struct PreGrant<'a> {
    /// The registered client id.
    pub client_id: Cow<'a, str>,

    /// The redirection url associated with the above client.
    pub redirect_url: Cow<'a, Url>,

    /// A scope admissible for the above client.
    pub scope: Cow<'a, Scope>,
}

/// Handled responses from a registrar.
pub enum RegistrarError {
    /// Indicates an entirely unknown client.
    Unregistered,

    /// The redirection url was not the registered one.
    ///
    /// It is generally advisable to perform an exact match on the url, to prevent injection of
    /// bad query parameters for example but not strictly required.
    MismatchedRedirect,

    /// The client is not authorized.
    UnauthorizedClient,
}

/// Clients are registered users of authorization tokens.
///
/// There are two types of clients, public and confidential. Public clients operate without proof
/// of identity while confidential clients are granted additional assertions on their communication
/// with the servers. They might be allowed more freedom as they are harder to impersonate.
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

impl<'a> BoundClient<'a> {
    pub fn negotiate(self, scope: Option<Scope>) -> PreGrant<'a> {
        PreGrant {
            client_id: self.client_id,
            redirect_url: self.redirect_url,
            scope: Cow::Owned(self.client.default_scope.clone()),
        }
    }
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
    /// Create an empty map without any clients in it.
    pub fn new() -> ClientMap {
        ClientMap { clients: HashMap::new() }
    }

    /// Insert or update the client record.
    pub fn register_client(&mut self, client: Client) {
        self.clients.insert(client.client_id.clone(), client);
    }
}

impl Registrar for ClientMap {
    fn bound_redirect<'a>(&'a self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        let client = match self.clients.get(bound.client_id.as_ref()) {
            None => return Err(RegistrarError::Unregistered),
            Some(stored) => stored
        };

        // Perform exact matching as motivated in the rfc
        match bound.redirect_url {
            None => (),
            Some(ref url) if *url.as_ref() == client.redirect_url => (),
            _ => return Err(RegistrarError::MismatchedRedirect),
        }

        Ok(BoundClient{
            client_id: bound.client_id,
            redirect_url: bound.redirect_url.unwrap_or_else(
                || Cow::Owned(client.redirect_url.clone())),
            client: client})
    }

    fn client(&self, client_id: &str) -> Option<&Client> {
        self.clients.get(client_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_client() {
        let client = Client::public("ClientId", "https://example.com".parse().unwrap(),
            "default".parse().unwrap());
        assert!(client.check_authentication(None).is_ok());
        assert!(client.check_authentication(Some(b"")).is_err());
    }

    #[test]
    fn confidential_client() {
        let pass = b"AB3fAj6GJpdxmEVeNCyPoA==";
        let client = Client::confidential("ClientId", "https://example.com".parse().unwrap(),
            "default".parse().unwrap(), pass);
        assert!(client.check_authentication(None).is_err());
        assert!(client.check_authentication(Some(pass)).is_ok());
        assert!(client.check_authentication(Some(b"not the passphrase")).is_err());
        assert!(client.check_authentication(Some(b"")).is_err());
    }
}
