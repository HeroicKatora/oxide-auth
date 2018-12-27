//! Registrars administer a database of known clients.
//!
//! It will govern their redirect urls and allowed scopes to request tokens for. When an oauth
//! request turns up, it is the registrars duty to verify the requested scope and redirect url for
//! consistency in the permissions granted and urls registered.
use super::scope::Scope;

use std::borrow::Cow;
use std::cmp;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, MutexGuard, RwLockWriteGuard};
use std::rc::Rc;

use url::Url;
use ring::{digest, pbkdf2};
use ring::error::Unspecified;
use ring::rand::{SystemRandom, SecureRandom};

/// Registrars provie a way to interact with clients.
///
/// Most importantly, they determine defaulted parameters for a request as well as the validity
/// of provided parameters. In general, implementations of this trait will probably offer an
/// interface for registering new clients. This interface is not covered by this library.
pub trait Registrar {
    /// Determine the allowed scope and redirection url for the client. The registrar may override
    /// the scope entirely or simply substitute a default scope in case none is given. Redirection
    /// urls should be matched verbatim, not partially.
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError>;

    /// Finish the negotiations with the registrar.
    ///
    /// The registrar is responsible for choosing the appropriate scope for the client. In the most
    /// simple case, it will always choose some default scope for the client, regardless of its
    /// wish. The standard permits this but requires the client to be notified of the resulting
    /// scope of the token in such a case, when it retrieves its token via the access token
    /// request.
    ///
    /// Another common strategy is to set a default scope or return the intersection with another
    /// scope.
    fn negotiate(&self, client: BoundClient, scope: Option<Scope>) -> Result<PreGrant, RegistrarError>;

    /// Try to login as client with some authentication.
    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError>;
}

/// A pair of `client_id` and an optional `redirect_uri`.
///
/// Such a pair is received in an Authorization Code Request. A registrar which allows multiple
/// urls per client can use the optional parameter to choose the correct url. A prominent example
/// is a native client which uses opens a local port to receive the redirect. Since it can not
/// necessarily predict the port, the open port needs to be communicated to the server (Note: this
/// mechanism is not provided by the simple `ClientMap` implementation).
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
pub struct BoundClient<'a> {
    /// The identifier of the client, moved from the request.
    pub client_id: Cow<'a, str>,

    /// The chosen redirection endpoint url, moved from the request or overwritten.
    pub redirect_uri: Cow<'a, Url>,
}

/// These are the parameters presented to the resource owner when confirming or denying a grant
/// request. Together with the owner_id and a computed expiration time stamp, this will form a
/// grant of some sort. In the case of the authorization code grant flow, it will be an
/// authorization code at first, which can be traded for an access code by the client acknowledged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreGrant {
    /// The registered client id.
    pub client_id: String,

    /// The redirection url associated with the above client.
    pub redirect_uri: Url,

    /// A scope admissible for the above client.
    pub scope: Scope,
}

/// Handled responses from a registrar.
#[derive(Clone, Debug)]
pub enum RegistrarError {
    /// One of several different causes that should be indistiguishable.
    ///
    /// * Indicates an entirely unknown client.
    /// * The client is not authorized.
    /// * The redirection url was not the registered one.  It is generally advisable to perform an
    ///   exact match on the url, to prevent injection of bad query parameters for example but not
    ///   strictly required.
    ///
    /// These should be indistiguishable to avoid security problems.
    Unspecified,

    /// Something went wrong with this primitive that has no security reason.
    PrimitiveError,
}

/// Clients are registered users of authorization tokens.
///
/// There are two types of clients, public and confidential. Public clients operate without proof
/// of identity while confidential clients are granted additional assertions on their communication
/// with the servers. They might be allowed more freedom as they are harder to impersonate.
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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
#[derive(Clone)]
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

impl fmt::Debug for ClientType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            ClientType::Public => write!(f, "<public>"),
            ClientType::Confidential { .. } => write!(f, "<confidential>"),
        }
    }
}

impl From<Unspecified> for RegistrarError {
    fn from(err: Unspecified) -> Self {
        match err { Unspecified => RegistrarError::Unspecified }
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
    pub fn check_authentication(&self, passphrase: Option<&[u8]>) -> Result<(), Unspecified> {
        match (passphrase, &self.client.encoded_client) {
            (None, &ClientType::Public) => Ok(()),
            (Some(provided), &ClientType::Confidential{ passdata: ref stored })
                => self.policy.check(&self.client.client_id, provided, stored),
            _ => return Err(Unspecified)
        }
    }
}

impl cmp::PartialOrd<Self> for PreGrant {
    /// `PreGrant` is compared by scope if `client_id` and `redirect_uri` are equal.
    fn partial_cmp(&self, rhs: &PreGrant) -> Option<cmp::Ordering> {
        if (&self.client_id, &self.redirect_uri) != (&rhs.client_id, &rhs.redirect_uri) {
            None
        } else {
            self.scope.partial_cmp(&rhs.scope)
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

struct Pbkdf2 {
    /// A prebuilt random, or constructing one as needed.
    random: Option<SystemRandom>,
    iterations: u32,
}

impl Default for Pbkdf2 {
    fn default() -> Self {
        Pbkdf2 {
            random: Some(SystemRandom::new()),
            .. *Self::static_default()
        }
    }
}

impl Clone for Pbkdf2 {
    fn clone(&self) -> Self {
        Pbkdf2 {
            random: Some(SystemRandom::new()),
            .. *self
        }
    }
}

impl fmt::Debug for Pbkdf2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Pbkdf2")
            .field("iterations", &self.iterations)
            .field("random", &())
            .finish()
    }
}

impl Pbkdf2 {
    fn static_default() -> &'static Self {
        &Pbkdf2 {
            random: None,
            iterations: 100_000,
        }
    }

    fn salt(&self, user_identifier: &[u8]) -> Vec<u8> {
        let mut vec = Vec::with_capacity(user_identifier.len() + 64);
        let mut rnd_salt = [0; 16];

        match self.random.as_ref() {
            Some(random) => random.fill(&mut rnd_salt),
            None => SystemRandom::new().fill(&mut rnd_salt),
        }.expect("Failed to property initialize password storage salt");

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
        -> Result<(), Unspecified>
    {
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

impl<'s, R: Registrar + ?Sized> Registrar for &'s R {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        (**self).bound_redirect(bound)
    }

    fn negotiate(&self, bound: BoundClient, scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        (**self).negotiate(bound, scope)
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        (**self).check(client_id, passphrase)
    }
}

impl<'s, R: Registrar + ?Sized> Registrar for &'s mut R {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        (**self).bound_redirect(bound)
    }

    fn negotiate(&self, bound: BoundClient, scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        (**self).negotiate(bound, scope)
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        (**self).check(client_id, passphrase)
    }
}

impl<R: Registrar + ?Sized> Registrar for Box<R> {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        (**self).bound_redirect(bound)
    }

    fn negotiate(&self, bound: BoundClient, scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        (**self).negotiate(bound, scope)
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        (**self).check(client_id, passphrase)
    }
}

impl<R: Registrar + ?Sized> Registrar for Rc<R> {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        (**self).bound_redirect(bound)
    }

    fn negotiate(&self, bound: BoundClient, scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        (**self).negotiate(bound, scope)
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        (**self).check(client_id, passphrase)
    }
}

impl<R: Registrar + ?Sized> Registrar for Arc<R> {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        (**self).bound_redirect(bound)
    }

    fn negotiate(&self, bound: BoundClient, scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        (**self).negotiate(bound, scope)
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        (**self).check(client_id, passphrase)
    }
}

impl<'s, R: Registrar + ?Sized + 's> Registrar for MutexGuard<'s, R> {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        (**self).bound_redirect(bound)
    }

    fn negotiate(&self, bound: BoundClient, scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        (**self).negotiate(bound, scope)
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        (**self).check(client_id, passphrase)
    }
}

impl<'s, R: Registrar + ?Sized + 's> Registrar for RwLockWriteGuard<'s, R> {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        (**self).bound_redirect(bound)
    }

    fn negotiate(&self, bound: BoundClient, scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        (**self).negotiate(bound, scope)
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        (**self).check(client_id, passphrase)
    }
}

impl Registrar for ClientMap {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        let client = match self.clients.get(bound.client_id.as_ref()) {
            None => return Err(RegistrarError::Unspecified),
            Some(stored) => stored
        };

        // Perform exact matching as motivated in the rfc
        match bound.redirect_uri {
            None => (),
            Some(ref url) if url.as_ref().as_str() == client.redirect_uri.as_str() => (),
            _ => return Err(RegistrarError::Unspecified),
        }

        Ok(BoundClient {
            client_id: bound.client_id,
            redirect_uri: bound.redirect_uri.unwrap_or_else(
                || Cow::Owned(client.redirect_uri.clone())),
        })
    }

    /// Always overrides the scope with a default scope.
    fn negotiate(&self, bound: BoundClient, _scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        let client = self.clients.get(bound.client_id.as_ref())
            .expect("Bound client appears to not have been constructed with this registrar");
        Ok(PreGrant {
            client_id: bound.client_id.into_owned(),
            redirect_uri: bound.redirect_uri.into_owned(),
            scope: client.default_scope.clone(),
        })
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        let password_policy = Self::current_policy(&self.password_policy);

        self.clients.get(client_id)
            .ok_or(Unspecified)
            .and_then(|client| RegisteredClient::new(client, password_policy)
                .check_authentication(passphrase))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            registrar.check(public_id, None)
                .expect("Authorization of public client has changed");
            registrar.check(public_id, Some(b""))
                .err().expect("Authorization with password succeeded");
        }

        let private_client = Client::confidential(private_id, client_url.parse().unwrap(),
            "default".parse().unwrap(), private_passphrase);

        register(registrar, private_client);

        {
            registrar.check(private_id, Some(private_passphrase))
                .expect("Authorization with right password did not succeed");
            registrar.check(private_id, Some(b"Not the private passphrase"))
                .err().expect("Authorization succeed with wrong password");
        }
    }

    #[test]
    fn public_client() {
        let policy = Pbkdf2::default();
        let client = Client::public(
            "ClientId",
            "https://example.com".parse().unwrap(),
            "default".parse().unwrap()
        ).encode(&policy);
        let client = RegisteredClient::new(&client, &policy);

        // Providing no authentication data is ok
        assert!(client.check_authentication(None).is_ok());
        // Any authentication data is a fail
        assert!(client.check_authentication(Some(b"")).is_err());
    }

    #[test]
    fn confidential_client() {
        let policy = Pbkdf2::default();
        let pass = b"AB3fAj6GJpdxmEVeNCyPoA==";
        let client = Client::confidential(
            "ClientId",
            "https://example.com".parse().unwrap(),
            "default".parse().unwrap(),
            pass
        ).encode(&policy);
        let client = RegisteredClient::new(&client, &policy);
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
