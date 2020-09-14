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
use std::iter::{Extend, FromIterator};
use std::rc::Rc;
use std::sync::{Arc, MutexGuard, RwLockWriteGuard};

use argon2::{self, Config};
use once_cell::sync::Lazy;
use rand::{RngCore, thread_rng};
use url::{Url, ParseError as ParseUrlError};

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

/// An url that has been registered.
///
/// There are two ways to create this url:
///
/// 1. By supplying a string to match _exactly_
/// 2. By an URL which needs to match semantically.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegisteredUrl {
    /// An exact URL that must be match literally when the client uses it.
    ///
    /// The string still needs to form a valid URL. See the documentation of [`ExactUrl`] for more
    /// information on when to use this variant and guarantees.
    ///
    /// [`ExactUrl`]: struct.ExactUrl.html
    Exact(ExactUrl),
    /// An URL that needs to match the redirect URL semantically.
    Semantic(Url),
}

/// A redirect URL that must be matched exactly by the client.
///
/// Semantically these URLs are all the same:
///
/// * `https://client.example/oauth2/redirect`
/// * `https://client.example/oauth2/redirect/`
/// * `https://client.example/oauth2/../oauth2/redirect/`
/// * `https://client.example:443/oauth2/redirect`
///
/// When the URL is parsed then typically one canonical form is chosen by the parsing library. When
/// a string comparison is done then all other do not match the expected value that was originally
/// passed to the registration. This type always stores the original string instead.
///
/// The comparison is done character-by-character, i.e. it's not constant time. While this entry is
/// not sensitive like a password, it is reasonable for a server to e.g. apply bloom filters or
/// store an URL in a compressed form such as a hash. However, such a transition would not be
/// possible if clients are allowed to provide any semantically matching URL as there are
/// infinitely many with different hashes. (Note: a hashed form of URL storage is not currently
/// supported).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactUrl(String);

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
    pub redirect_uri: Option<Cow<'a, ExactUrl>>,
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
    pub redirect_uri: Cow<'a, RegisteredUrl>,
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
    pub redirect_uri: RegisteredUrl,

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
// TODO(from #29): allow verbatim urls. Parsing to Url instigates some normalization making the
// string representation less predictable. A verbatim url would allow comparing the `redirect_uri`
// parameter with simple string comparison, a potential speedup.
// TODO: there is no more an apparent reason for this to be a strictly owning struct.
#[derive(Clone, Debug)]
pub struct Client {
    client_id: String,
    redirect_uri: RegisteredUrl,
    additional_redirect_uris: Vec<RegisteredUrl>,
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
    /// Unlike `additional_redirect_uris`, this is registered as the default redirect uri
    /// and will be replaced if, for example, no `redirect_uri` is specified in the request parameter.
    pub redirect_uri: RegisteredUrl,

    /// The redirect uris that can be registered in addition to the `redirect_uri`.
    /// If you want to register multiple redirect uris, register them together with `redirect_uri`.
    pub additional_redirect_uris: Vec<RegisteredUrl>,

    /// The scope the client gets if none was given.
    pub default_scope: Scope,

    /// The authentication data.
    pub encoded_client: ClientType,
}

/// Recombines an `EncodedClient` and a  `PasswordPolicy` to check authentication.
pub struct RegisteredClient<'a> {
    client: &'a EncodedClient,
    policy: &'a dyn PasswordPolicy,
}

/// Enumeration of the two defined client types.
#[derive(Clone)]
pub enum ClientType {
    /// A public client with no authentication information.
    Public,

    /// A confidential client who needs to be authenticated before communicating.
    Confidential {
        /// Byte data encoding the password authentication under the used policy.
        passdata: Vec<u8>,
    },
}

/// A very simple, in-memory hash map of client ids to Client entries.
#[derive(Default)]
pub struct ClientMap {
    clients: HashMap<String, EncodedClient>,
    password_policy: Option<Box<dyn PasswordPolicy>>,
}

impl fmt::Debug for ClientType {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            ClientType::Public => write!(f, "<public>"),
            ClientType::Confidential { .. } => write!(f, "<confidential>"),
        }
    }
}

impl RegisteredUrl {
    /// View the url as a string.
    pub fn as_str(&self) -> &str {
        match self {
            RegisteredUrl::Exact(exact) => &exact.0,
            RegisteredUrl::Semantic(url) => url.as_str(),
        }
    }

    /// Turn the url into a semantic `Url`.
    pub fn to_url(&self) -> Url {
        match self {
            RegisteredUrl::Exact(exact) => exact.to_url(),
            RegisteredUrl::Semantic(url) => url.clone(),
        }
    }

    /// Turn the url into a semantic `Url`.
    pub fn into_url(self) -> Url {
        self.into()
    }
}

impl From<Url> for RegisteredUrl {
    fn from(url: Url) -> Self {
        RegisteredUrl::Semantic(url)
    }
}

impl From<ExactUrl> for RegisteredUrl {
    fn from(url: ExactUrl) -> Self {
        RegisteredUrl::Exact(url)
    }
}

impl From<RegisteredUrl> for Url {
    fn from(url: RegisteredUrl) -> Self {
        match url {
            RegisteredUrl::Exact(exact) => exact.0.parse().expect("was validated"),
            RegisteredUrl::Semantic(url) => url,
        }
    }
}

/// Compares the registered url as an exact string if it was registered as exact, otherwise
/// semantically.
impl cmp::PartialEq<ExactUrl> for RegisteredUrl {
    fn eq(&self, exact: &ExactUrl) -> bool {
        match self {
            RegisteredUrl::Exact(url) => url == exact,
            RegisteredUrl::Semantic(url) => *url == exact.to_url(),
        }
    }
}

/// Compares the registered url semantically.
impl cmp::PartialEq<Url> for RegisteredUrl {
    fn eq(&self, semantic: &Url) -> bool {
        self.to_url() == *semantic
    }
}

impl fmt::Display for RegisteredUrl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RegisteredUrl::Exact(url) => write!(f, "{}", url.to_url()),
            RegisteredUrl::Semantic(url) => write!(f, "{}", url),
        }
    }
}

impl ExactUrl {
    /// Try to create an exact url from a string.
    pub fn new(url: String) -> Result<Self, ParseUrlError> {
        let _: Url = url.parse()?;
        Ok(ExactUrl(url))
    }

    /// View the url as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Turn the url into a semantic `Url`.
    pub fn to_url(&self) -> Url {
        // TODO: maybe we should store the parsing result?
        self.0.parse().expect("was validated")
    }
}

impl core::str::FromStr for ExactUrl {
    type Err = ParseUrlError;
    fn from_str(st: &str) -> Result<Self, Self::Err> {
        let _: Url = st.parse()?;
        Ok(ExactUrl(st.to_string()))
    }
}

impl Client {
    /// Create a public client.
    pub fn public(client_id: &str, redirect_uri: RegisteredUrl, default_scope: Scope) -> Client {
        Client {
            client_id: client_id.to_string(),
            redirect_uri,
            additional_redirect_uris: vec![],
            default_scope,
            client_type: ClientType::Public,
        }
    }

    /// Create a confidential client.
    pub fn confidential(
        client_id: &str, redirect_uri: RegisteredUrl, default_scope: Scope, passphrase: &[u8],
    ) -> Client {
        Client {
            client_id: client_id.to_string(),
            redirect_uri,
            additional_redirect_uris: vec![],
            default_scope,
            client_type: ClientType::Confidential {
                passdata: passphrase.to_owned(),
            },
        }
    }

    /// Add additional redirect uris.
    pub fn with_additional_redirect_uris(mut self, uris: Vec<RegisteredUrl>) -> Self {
        self.additional_redirect_uris = uris;
        self
    }

    /// Obscure the clients authentication data.
    ///
    /// This could apply a one-way function to the passphrase using an adequate password hashing
    /// method. The resulting passdata is then used for validating authentication details provided
    /// when later reasserting the identity of a client.
    pub fn encode(self, policy: &dyn PasswordPolicy) -> EncodedClient {
        let encoded_client = match self.client_type {
            ClientType::Public => ClientType::Public,
            ClientType::Confidential { passdata: passphrase } => ClientType::Confidential {
                passdata: policy.store(&self.client_id, &passphrase),
            },
        };

        EncodedClient {
            client_id: self.client_id,
            redirect_uri: self.redirect_uri,
            additional_redirect_uris: self.additional_redirect_uris,
            default_scope: self.default_scope,
            encoded_client,
        }
    }
}

impl<'a> RegisteredClient<'a> {
    /// Binds a client and a policy reference together.
    ///
    /// The policy should be the same or equivalent to the policy used to create the encoded client
    /// data, as otherwise authentication will obviously not work.
    pub fn new(client: &'a EncodedClient, policy: &'a dyn PasswordPolicy) -> Self {
        RegisteredClient { client, policy }
    }

    /// Try to authenticate with the client and passphrase. This check will success if either the
    /// client is public and no passphrase was provided or if the client is confidential and the
    /// passphrase matches.
    pub fn check_authentication(&self, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        match (passphrase, &self.client.encoded_client) {
            (None, &ClientType::Public) => Ok(()),
            (Some(provided), &ClientType::Confidential { passdata: ref stored }) => {
                self.policy.check(&self.client.client_id, provided, stored)
            }
            _ => Err(RegistrarError::Unspecified),
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

/// Determines how passphrases are stored and checked.
///
/// The provided library implementation is based on `Argon2`.
pub trait PasswordPolicy: Send + Sync {
    /// Transform the passphrase so it can be stored in the confidential client.
    fn store(&self, client_id: &str, passphrase: &[u8]) -> Vec<u8>;

    /// Check if the stored data corresponds to that of the client id and passphrase.
    fn check(&self, client_id: &str, passphrase: &[u8], stored: &[u8]) -> Result<(), RegistrarError>;
}

/// Store passwords using `Argon2` to derive the stored value.
#[derive(Clone, Debug, Default)]
pub struct Argon2 {
    _private: (),
}

impl PasswordPolicy for Argon2 {
    fn store(&self, client_id: &str, passphrase: &[u8]) -> Vec<u8> {
        let mut config = Config::default();
        config.ad = client_id.as_bytes();
        config.secret = &[];

        let mut salt = vec![0; 32];
        thread_rng()
            .try_fill_bytes(salt.as_mut_slice())
            .expect("Failed to generate password salt");

        let encoded = argon2::hash_encoded(passphrase, &salt, &config);
        encoded.unwrap().as_bytes().to_vec()
    }

    fn check(&self, client_id: &str, passphrase: &[u8], stored: &[u8]) -> Result<(), RegistrarError> {
        let hash = String::from_utf8(stored.to_vec()).map_err(|_| RegistrarError::PrimitiveError)?;
        let valid = argon2::verify_encoded_ext(&hash, passphrase, &[], client_id.as_bytes())
            .map_err(|_| RegistrarError::PrimitiveError)?;
        match valid {
            true => Ok(()),
            false => Err(RegistrarError::Unspecified),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//                             Standard Implementations of Registrars                            //
///////////////////////////////////////////////////////////////////////////////////////////////////

static DEFAULT_PASSWORD_POLICY: Lazy<Argon2> = Lazy::new(Argon2::default);

impl ClientMap {
    /// Create an empty map without any clients in it.
    pub fn new() -> ClientMap {
        ClientMap::default()
    }

    /// Insert or update the client record.
    pub fn register_client(&mut self, client: Client) {
        let password_policy = Self::current_policy(&self.password_policy);
        self.clients
            .insert(client.client_id.clone(), client.encode(password_policy));
    }

    /// Change how passwords are encoded while stored.
    pub fn set_password_policy<P: PasswordPolicy + 'static>(&mut self, new_policy: P) {
        self.password_policy = Some(Box::new(new_policy))
    }

    // This is not an instance method because it needs to borrow the box but register needs &mut
    fn current_policy<'a>(policy: &'a Option<Box<dyn PasswordPolicy>>) -> &'a dyn PasswordPolicy {
        policy
            .as_ref()
            .map(|boxed| &**boxed)
            .unwrap_or(&*DEFAULT_PASSWORD_POLICY)
    }
}

impl Extend<Client> for ClientMap {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Client>,
    {
        iter.into_iter().for_each(|client| self.register_client(client))
    }
}

impl FromIterator<Client> for ClientMap {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = Client>,
    {
        let mut into = ClientMap::new();
        into.extend(iter);
        into
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
            Some(stored) => stored,
        };

        // Perform exact matching as motivated in the rfc
        let registered_url = match bound.redirect_uri {
            None => client.redirect_uri.clone(),
            Some(ref url) => {
                let original = std::iter::once(&client.redirect_uri);
                let alternatives = client.additional_redirect_uris.iter();
                if let Some(registered) = original
                    .chain(alternatives)
                    .find(|&registered| *registered == *url.as_ref())
                {
                    registered.clone()
                } else {
                    return Err(RegistrarError::Unspecified);
                }
            }
        };

        Ok(BoundClient {
            client_id: bound.client_id,
            redirect_uri: Cow::Owned(registered_url),
        })
    }

    /// Always overrides the scope with a default scope.
    fn negotiate(&self, bound: BoundClient, _scope: Option<Scope>) -> Result<PreGrant, RegistrarError> {
        let client = self
            .clients
            .get(bound.client_id.as_ref())
            .expect("Bound client appears to not have been constructed with this registrar");
        Ok(PreGrant {
            client_id: bound.client_id.into_owned(),
            redirect_uri: bound.redirect_uri.into_owned(),
            scope: client.default_scope.clone(),
        })
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        let password_policy = Self::current_policy(&self.password_policy);

        self.clients
            .get(client_id)
            .ok_or(RegistrarError::Unspecified)
            .and_then(|client| {
                RegisteredClient::new(client, password_policy).check_authentication(passphrase)
            })?;

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
        RegFn: Fn(&mut Reg, Client),
    {
        let public_id = "PrivateClientId";
        let client_url = "https://example.com";

        let private_id = "PublicClientId";
        let private_passphrase = b"WOJJCcS8WyS2aGmJK6ZADg==";

        let public_client = Client::public(
            public_id,
            client_url.parse::<Url>().unwrap().into(),
            "default".parse().unwrap(),
        );

        register(registrar, public_client);

        {
            registrar
                .check(public_id, None)
                .expect("Authorization of public client has changed");
            registrar
                .check(public_id, Some(b""))
                .err()
                .expect("Authorization with password succeeded");
        }

        let private_client = Client::confidential(
            private_id,
            client_url.parse::<Url>().unwrap().into(),
            "default".parse().unwrap(),
            private_passphrase,
        );

        register(registrar, private_client);

        {
            registrar
                .check(private_id, Some(private_passphrase))
                .expect("Authorization with right password did not succeed");
            registrar
                .check(private_id, Some(b"Not the private passphrase"))
                .err()
                .expect("Authorization succeed with wrong password");
        }
    }

    #[test]
    fn public_client() {
        let policy = Argon2::default();
        let client = Client::public(
            "ClientId",
            "https://example.com".parse::<Url>().unwrap().into(),
            "default".parse().unwrap(),
        )
        .encode(&policy);
        let client = RegisteredClient::new(&client, &policy);

        // Providing no authentication data is ok
        assert!(client.check_authentication(None).is_ok());
        // Any authentication data is a fail
        assert!(client.check_authentication(Some(b"")).is_err());
    }

    #[test]
    fn confidential_client() {
        let policy = Argon2::default();
        let pass = b"AB3fAj6GJpdxmEVeNCyPoA==";
        let client = Client::confidential(
            "ClientId",
            "https://example.com".parse::<Url>().unwrap().into(),
            "default".parse().unwrap(),
            pass,
        )
        .encode(&policy);
        let client = RegisteredClient::new(&client, &policy);
        assert!(client.check_authentication(None).is_err());
        assert!(client.check_authentication(Some(pass)).is_ok());
        assert!(client.check_authentication(Some(b"not the passphrase")).is_err());
        assert!(client.check_authentication(Some(b"")).is_err());
    }

    #[test]
    fn with_additional_redirect_uris() {
        let client_id = "ClientId";
        let redirect_uri: Url = "https://example.com/foo".parse().unwrap();
        let additional_redirect_uris: Vec<RegisteredUrl> =
            vec!["https://example.com/bar".parse::<Url>().unwrap().into()];
        let default_scope = "default".parse().unwrap();
        let client = Client::public(client_id, redirect_uri.into(), default_scope)
            .with_additional_redirect_uris(additional_redirect_uris);
        let mut client_map = ClientMap::new();
        client_map.register_client(client);

        assert_eq!(
            client_map
                .bound_redirect(ClientUrl {
                    client_id: Cow::from(client_id),
                    redirect_uri: Some(Cow::Borrowed(&"https://example.com/foo".parse().unwrap()))
                })
                .unwrap()
                .redirect_uri,
            Cow::<Url>::Owned("https://example.com/foo".parse().unwrap())
        );

        assert_eq!(
            client_map
                .bound_redirect(ClientUrl {
                    client_id: Cow::from(client_id),
                    redirect_uri: Some(Cow::Borrowed(&"https://example.com/bar".parse().unwrap()))
                })
                .unwrap()
                .redirect_uri,
            Cow::<Url>::Owned("https://example.com/bar".parse().unwrap())
        );

        assert!(client_map
            .bound_redirect(ClientUrl {
                client_id: Cow::from(client_id),
                redirect_uri: Some(Cow::Borrowed(&"https://example.com/baz".parse().unwrap()))
            })
            .is_err());
    }

    #[test]
    fn client_map() {
        let mut client_map = ClientMap::new();
        simple_test_suite(&mut client_map, ClientMap::register_client);
    }
}
