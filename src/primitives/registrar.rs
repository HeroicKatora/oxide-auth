//! Registrars administer a database of known clients.
//!
//! It will govern their redirect urls and allowed scopes to request tokens for. When an oauth
//! request turns up, it is the registrars duty to verify the requested scope and redirect url for
//! consistency in the permissions granted and urls registered.
use super::scope::Scope;
use std::borrow::Cow;
use std::collections::HashMap;
use url::Url;
use ring::{constant_time, digest, pbkdf2};
use ring::error::Unspecified;
use rand;

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
    fn client(&self, client_id: &str) -> Option<RegisteredClient>;
}

/// A pair of `client_id` and an optional `redirect_uri`.
///
/// Such a pair is received in an Authorization Code Request. A registrar which allows multiple
/// urls per client can use the optional parameter to choose the correct url. A prominent example
/// is a native client which uses opens a local port to receive the redirect. Since it can not
/// necessarily predict the port, the open port needs to be communicated to the server (Note: this
/// mechanism is not provided by the simple `ClientMap` implementation).
pub struct ClientUrl<'a> {
    /// The identifier indicated
    pub client_id: Cow<'a, str>,

    /// The parsed url, if any.
    pub redirect_uri: Option<Cow<'a, Url>>,
}

/// A client and its chosen redirection endpoint.
///
/// This instance can be used to complete parameter negotiation with the registrar. In the simplest
/// case this only includes agreeing on a scope allowed for the client.
pub struct BoundClient<'a> {
    /// The identifier of the client, moved from the request.
    pub client_id: Cow<'a, str>,

    /// The chosen redirection endpoint url, moved from the request of overwritten.
    pub redirect_uri: Cow<'a, Url>,

    /// A reference to the client instance, for authentication and to retrieve additional
    /// information.
    pub client: &'a EncodedClient,
}

/// These are the parameters presented to the resource owner when confirming or denying a grant
/// request. Together with the owner_id and a computed expiration time stamp, this will form a
/// grant of some sort. In the case of the authorization code grant flow, it will be an
/// authorization code at first, which can be traded for an access code by the client acknowledged.
#[derive(Clone)]
pub struct PreGrant {
    /// The registered client id.
    pub client_id: String,

    /// The redirection url associated with the above client.
    pub redirect_uri: Url,

    /// A scope admissible for the above client.
    pub scope: Scope,
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
    redirect_uri: Url,
    default_scope: Scope,
    client_type: ClientType,
}

/// A client whose credentials have been wrapped by a password policy.
///
/// This provides a standard encoding for `Registrars` who wish to store their clients and makes it
/// possible to test password policies.
pub struct EncodedClient {
    /// The id of this client. If this is was registered at a `Registrar`, this should be a key
    /// to the instance.
    pub client_id: String,

    /// The registered redirect uri.
    pub redirect_uri: Url,

    /// The scope the client gets if none was given.
    pub default_scope: Scope,

    /// The authentication data.
    pub encoded_client: ClientType,
}

/// Recombines an `EncodedClient` and a  `PasswordPolicy` to check authentication.
pub struct RegisteredClient<'a> {
    client: &'a EncodedClient,
    policy: &'a PasswordPolicy,
}

/// Enumeration of the two defined client types.
pub enum ClientType {
    /// A public client with no authentication information.
    Public,

    /// A confidential client who needs to be authenticated before communicating.
    Confidential{
        /// Byte data encoding the password authentication under the used policy.
        passdata: Vec<u8>,
    },
}

/// A very simple, in-memory hash map of client ids to Client entries.
pub struct ClientMap {
    clients: HashMap<String, EncodedClient>,
    password_policy: Option<Box<PasswordPolicy>>,
}

impl<'a> BoundClient<'a> {
    /// Finish the negotiations with the registrar.
    ///
    /// The registrar is responsible for choosing the appropriate scope for the client. In the most
    /// simple case, it will always choose some default scope for the client, regardless of its
    /// wish. The standard permits this but requires the client to be notified of the resulting
    /// scope of the token in such a case, when it retrieves its token via the access token
    /// request.
    ///
    /// Currently, this scope agreement algorithm is the only supported method.
    pub fn negotiate(self, _scope: Option<Scope>) -> PreGrant {
        PreGrant {
            client_id: self.client_id.into_owned(),
            redirect_uri: self.redirect_uri.into_owned(),
            scope: self.client.default_scope.clone(),
        }
    }
}

impl Client {
    /// Create a public client.
    pub fn public(client_id: &str, redirect_uri: Url, default_scope: Scope) -> Client {
        Client { client_id: client_id.to_string(), redirect_uri, default_scope, client_type: ClientType::Public }
    }

    /// Create a confidential client.
    pub fn confidential(client_id: &str, redirect_uri: Url, default_scope: Scope, passphrase: &[u8]) -> Client {
        Client {
            client_id: client_id.to_string(),
            redirect_uri,
            default_scope,
            client_type: ClientType::Confidential {
                passdata: passphrase.to_owned()
            },
        }
    }

    /// Obscure the clients authentication data.
    ///
    /// This could apply a one-way function to the passphrase using an adequate password hashing
    /// method. The resulting passdata is then used for validating authentication details provided
    /// when later reasserting the identity of a client.
    pub fn encode(self, policy: &PasswordPolicy) -> EncodedClient {
        let encoded_client = match self.client_type {
            ClientType::Public => ClientType::Public,
            ClientType::Confidential { passdata: passphrase }
                => ClientType::Confidential {
                    passdata: policy.store(&self.client_id, &passphrase)
                }
        };

        EncodedClient {
            client_id: self.client_id,
            redirect_uri: self.redirect_uri,
            default_scope: self.default_scope,
            encoded_client
        }
    }
}

impl<'a> RegisteredClient<'a> {
    /// Binds a client and a policy reference together.
    ///
    /// The policy should be the same or equivalent to the policy used to create the encoded client
    /// data, as otherwise authentication will obviously not work.
    pub fn new(client: &'a EncodedClient, policy: &'a PasswordPolicy) -> Self {
        RegisteredClient {
            client,
            policy,
        }
    }

    /// Try to authenticate with the client and passphrase. This check will success if either the
    /// client is public and no passphrase was provided or if the client is confidential and the
    /// passphrase matches.
    pub fn check_authentication(&self, passphrase: Option<&[u8]>) -> Result<&Self, Unspecified> {
        match (passphrase, &self.client.encoded_client) {
            (None, &ClientType::Public) => Ok(self),
            (Some(provided), &ClientType::Confidential{ passdata: ref stored })
                => self.policy.check(&self.client.client_id, provided, stored).map(|()| self),
            _ => return Err(Unspecified)
        }
    }
}

/// Determines how passphrases are stored and checked. Most likely you want to use Argon2
pub trait PasswordPolicy: Send + Sync {
    /// Transform the passphrase so it can be stored in the confidential client.
    fn store(&self, client_id: &str, passphrase: &[u8]) -> Vec<u8>;

    /// Check if the stored data corresponds to that of the client id and passphrase.
    fn check(&self, client_id: &str, passphrase: &[u8], stored: &[u8]) -> Result<(), Unspecified>;
}

/// Hashes the passphrase, salting with the client id. This is not optimal for passwords and will
/// be replaced with argon2 in a future commit which also enables better configurability, such as
/// supplying a secret key to argon2. This will probably be combined with a slight rework of the
/// exact semantics of `Client` and `Client::check_authentication`.
#[deprecated(since="0.1.0-alpha.1",
             note="Should be replaced with argon2 as soon as possible. Will be remove in 0.4")]
#[allow(dead_code)]
struct SHA256Policy;

#[allow(deprecated)]
impl PasswordPolicy for SHA256Policy {
    fn store(&self, client_id: &str, passphrase: &[u8]) -> Vec<u8> {
        // let salt = [0; 16];
        // ring::rand::SecureRandom
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

#[derive(Clone, Debug)]
struct Pbkdf2 {
    iterations: u32,
}

impl Default for Pbkdf2 {
    fn default() -> Self {
        Self::static_default().clone()
    }
}

impl Pbkdf2 {
    fn static_default() -> &'static Self {
        &Pbkdf2 {
            iterations: 100_000,
        }
    }

    fn salt(&self, user_identifier: &[u8]) -> Vec<u8> {
        let mut vec = Vec::with_capacity(user_identifier.len() + 64);
        let rnd_salt: [u8; 16] = rand::random();
        vec.extend_from_slice(user_identifier);
        vec.extend_from_slice(&rnd_salt[..]);
        vec
    }
}

impl PasswordPolicy for Pbkdf2 {
    fn store(&self, client_id: &str, passphrase: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(64);
        output.resize(64, 0);
        output.append(&mut self.salt(client_id.as_bytes()));
        {
            let (output, salt) = output.split_at_mut(64);
            pbkdf2::derive(&digest::SHA256, self.iterations, salt, passphrase,
                output);
        }
        output
    }

    fn check(&self, _client_id: &str /* Was interned */, passphrase: &[u8], stored: &[u8])
    -> Result<(), Unspecified> {
        if stored.len() < 64 {
            return Err(Unspecified)
        }

        let (verifier, salt) = stored.split_at(64);
        pbkdf2::verify(&digest::SHA256, self.iterations, salt, passphrase, verifier)
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//                             Standard Implementations of Registrars                            //
///////////////////////////////////////////////////////////////////////////////////////////////////

impl ClientMap {
    /// Create an empty map without any clients in it.
    pub fn new() -> ClientMap {
        ClientMap {
            clients: HashMap::new(),
            password_policy: None,
        }
    }

    /// Insert or update the client record.
    pub fn register_client(&mut self, client: Client) {
        let password_policy = Self::current_policy(&self.password_policy);
        self.clients.insert(client.client_id.clone(), client.encode(password_policy));
    }

    /// Change how passwords are encoded while stored.
    pub fn set_password_policy<P: PasswordPolicy + 'static>(&mut self, new_policy: P) {
        self.password_policy = Some(Box::new(new_policy))
    }

    // This is not an instance method because it needs to borrow the box but register needs &mut
    fn current_policy<'a>(policy: &'a Option<Box<PasswordPolicy>>) -> &'a PasswordPolicy {
        policy
            .as_ref().map(|boxed| &**boxed)
            .unwrap_or(Pbkdf2::static_default())
    }
}

impl Registrar for ClientMap {
    fn bound_redirect<'a>(&'a self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        let client = match self.clients.get(bound.client_id.as_ref()) {
            None => return Err(RegistrarError::Unregistered),
            Some(stored) => stored
        };

        // Perform exact matching as motivated in the rfc
        match bound.redirect_uri {
            None => (),
            Some(ref url) if url.as_ref().as_str() == client.redirect_uri.as_str() => (),
            _ => return Err(RegistrarError::MismatchedRedirect),
        }

        Ok(BoundClient {
            client_id: bound.client_id,
            redirect_uri: bound.redirect_uri.unwrap_or_else(
                || Cow::Owned(client.redirect_uri.clone())),
            client: client
        })
    }

    fn client(&self, client_id: &str) -> Option<RegisteredClient> {
        let password_policy = Self::current_policy(&self.password_policy);

        self.clients.get(client_id).map(|client| {
            RegisteredClient::new(client, password_policy)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No checking involved at all. This is a bad idea in a real system.
    struct NoCheckPolicy;

    impl PasswordPolicy for NoCheckPolicy {
        fn store(&self, _: &str, _: &[u8]) -> Vec<u8> {
            Vec::new()
        }

        fn check(&self, _: &str, _: &[u8], _: &[u8]) -> Result<(), Unspecified> {
            Ok(())
        }
    }

    // Literally save the password. Also a bad idea in a real system.
    struct PlaintextPolicy;

    impl PasswordPolicy for PlaintextPolicy {
        fn store(&self, _: &str, passphrase: &[u8]) -> Vec<u8> {
            passphrase.to_owned()
        }

        fn check(&self, _: &str, passphrase: &[u8], stored: &[u8]) -> Result<(), Unspecified> {
            constant_time::verify_slices_are_equal(passphrase, stored)
        }
    }

    /// A test suite for registrars which support simple registrations of arbitrary clients
    pub fn simple_test_suite<Reg, RegFn>(registrar: &mut Reg, register: RegFn)
    where
        Reg: Registrar,
        RegFn: Fn(&mut Reg, Client)
    {
        let public_id = "PrivateClientId";
        let client_url = "https://example.com";

        let private_id = "PublicClientId";
        let private_passphrase = b"WOJJCcS8WyS2aGmJK6ZADg==";

        let public_client = Client::public(public_id, client_url.parse().unwrap(),
            "default".parse().unwrap());

        register(registrar, public_client);

        {
            let recovered_client = registrar.client(public_id)
                .expect("Registered client not available");
            recovered_client.check_authentication(None)
                .expect("Authorization of public client has changed");
        }

        let private_client = Client::confidential(private_id, client_url.parse().unwrap(),
            "default".parse().unwrap(), private_passphrase);

        register(registrar, private_client);

        {
            let recovered_client = registrar.client(private_id)
                .expect("Registered client not available");
            recovered_client.check_authentication(Some(private_passphrase))
                .expect("Authorization of private client has changed");
        }
    }

    #[test]
    fn public_client() {
        let client = Client::public(
            "ClientId",
            "https://example.com".parse().unwrap(),
            "default".parse().unwrap()
        ).encode(&NoCheckPolicy);
        let client = RegisteredClient::new(&client, &NoCheckPolicy);

        // Providing no authentication data is ok
        assert!(client.check_authentication(None).is_ok());
        // Any authentication data is a fail
        assert!(client.check_authentication(Some(b"")).is_err());
    }

    #[test]
    fn confidential_client() {
        let pass = b"AB3fAj6GJpdxmEVeNCyPoA==";
        let client = Client::confidential(
            "ClientId",
            "https://example.com".parse().unwrap(),
            "default".parse().unwrap(),
            pass
        ).encode(&PlaintextPolicy);
        let client = RegisteredClient::new(&client, &PlaintextPolicy);
        assert!(client.check_authentication(None).is_err());
        assert!(client.check_authentication(Some(pass)).is_ok());
        assert!(client.check_authentication(Some(b"not the passphrase")).is_err());
        assert!(client.check_authentication(Some(b"")).is_err());
    }

    #[test]
    fn client_map() {
        let mut client_map = ClientMap::new();
        simple_test_suite(&mut client_map, ClientMap::register_client);
    }
}
