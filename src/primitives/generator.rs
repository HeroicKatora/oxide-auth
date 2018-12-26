//! Generators produce string code grant and bearer tokens for a determined grant.
//!
//! In short, a code grant needs to encapsulate information about the owner, client, redirect_uri,
//! scope, and lifetime of a grant. This information needs to be uniquely recoverable.
//!
//! Two major implementation exists:
//!     - `RandomGenerator` depends on the entropy of the generated token to make guessing
//!     infeasible.
//!     - `Assertion` cryptographically verifies the integrity of a token, trading security without
//!     persistent storage for the loss of revocability. It is thus unfit for some backends, which
//!     is not currently expressed in the type system or with traits.
use super::grant::{Extension, Extensions, Grant};
use super::{Url, Time};
use super::scope::Scope;

use std::collections::HashMap;

use base64::{encode, decode};
use ring::rand::{SystemRandom, SecureRandom};
use ring;
use rmp_serde;

/// Generic token for a specific grant.
///
/// The interface may be reused for authentication codes, bearer tokens and refresh tokens.
pub trait TokenGenerator {
    /// For example sign a grant or generate a random token.
    ///
    /// The exact guarantees and uses depend on the specific implementation. Implementation which
    /// do not support some grant may return an error instead.
    fn generate(&self, &Grant) -> Result<String, ()>;
}

/// Generates tokens from random bytes.
///
/// Each byte is chosen randomly from the basic `rand::thread_rng`. This generator will always
/// succeed.
pub struct RandomGenerator {
    random: SystemRandom,
    len: usize
}

impl RandomGenerator {
    /// Generates tokens with a specific byte length.
    pub fn new(length: usize) -> RandomGenerator {
        RandomGenerator {
            random: SystemRandom::new(),
            len: length
        }
    }
}

impl TokenGenerator for RandomGenerator {
    fn generate(&self, _grant: &Grant) -> Result<String, ()> {
        let mut result = vec![0; self.len];
        self.random.fill(result.as_mut_slice())
            .expect("Failed to generate random token");
        Ok(encode(&result))
    }
}

/// Generates tokens by signing its specifics with a private key.
///
/// Tokens produced by the generator include a serialized version of the grant followed by an HMAC
/// signature.  Since data is not encrypted, this token generator will ERROR if any private
/// extension is present in the grant.
///
/// The actual generator is given by a `TaggedAssertion` from `Assertion::tag` which enables
/// signing the same grant for different uses, i.e. separating authorization from bearer grants and
/// refresh tokens.
pub struct Assertion {
    secret: ring::hmac::SigningKey,
}

#[derive(Serialize, Deserialize)]
struct SerdeAssertionGrant {
    /// Identifies the owner of the resource.
    owner_id: String,

    /// Identifies the client to which the grant was issued.
    client_id: String,

    /// The scope granted to the client.
    #[serde(with = "scope_serde")]
    scope: Scope,

    /// The redirection uri under which the client resides. The url package does indeed seem to
    /// parse valid URIs as well.
    #[serde(with = "url_serde")]
    redirect_uri: Url,

    /// Expiration date of the grant (Utc).
    #[serde(with = "time_serde")]
    until: Time,

    /// The public extensions, private extensions not supported currently
    public_extensions: HashMap<String, Option<String>>,
}

#[derive(Serialize, Deserialize)]
struct AssertGrant(Vec<u8>, Vec<u8>);

/// Binds a tag to the data. The signature will be unique for data as well as the tag.
pub struct TaggedAssertion<'a>(&'a Assertion, &'a str);

impl Assertion {
    /// Construct an Assertion generator from a secret, private signing key.
    pub fn new(key: ring::hmac::SigningKey) -> Assertion {
        Assertion { secret: key}
    }

    /// Get a reference to generator for the given tag.
    pub fn tag<'a>(&'a self, tag: &'a str) -> TaggedAssertion<'a> {
        TaggedAssertion(self, tag)
    }

    fn extract<'a>(&self, token: &'a str) -> Result<(Grant, String), ()> {
        let decoded = decode(token).map_err(|_| ())?;
        let assertion: AssertGrant = rmp_serde::from_slice(&decoded).map_err(|_| ())?;
        ring::hmac::verify_with_own_key(&self.secret, &assertion.0, &assertion.1).map_err(|_| ())?;
        let (serde_grant, tag): (SerdeAssertionGrant, String)
            = rmp_serde::from_slice(&assertion.0).map_err(|_| ())?;
        Ok((serde_grant.grant(), tag))
    }

    fn generate_tagged(&self, grant: &Grant, tag: &str) -> Result<String, ()> {
        let serde_grant = SerdeAssertionGrant::try_from(grant)?;
        let tosign = rmp_serde::to_vec(&(serde_grant, tag)).unwrap();
        let signature = ring::hmac::sign(&self.secret, &tosign);
        Ok(encode(&rmp_serde::to_vec(&AssertGrant(tosign, signature.as_ref().to_vec())).unwrap()))
    }
}

impl<'a> TaggedAssertion<'a> {
    /// Inverse operation of generate, retrieve the underlying token.
    ///
    /// Result in an Err if either the signature is invalid or if the tag does not match the
    /// expected tag given to this assertion.
    pub fn extract<'b>(&self, token: &'b str) -> Result<Grant, ()> {
        self.0.extract(token).and_then(|(token, tag)| {
            if tag == self.1 {
                Ok(token)
            } else {
                Err(())
            }
        })
    }
}

impl<'a> TokenGenerator for TaggedAssertion<'a> {
    fn generate(&self, grant: &Grant) -> Result<String, ()> {
        self.0.generate_tagged(grant, self.1)
    }
}

mod scope_serde {
    use primitives::scope::Scope;

    use serde::ser::{Serializer};
    use serde::de::{Deserialize, Deserializer, Error};

    pub fn serialize<S: Serializer>(scope: &Scope, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&scope.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Scope, D::Error> {
        let as_string: &str = <(&str)>::deserialize(deserializer)?;
        as_string.parse().map_err(Error::custom)
    }
}

mod url_serde {
    use super::Url;

    use serde::ser::{Serializer};
    use serde::de::{Deserialize, Deserializer, Error};

    pub fn serialize<S: Serializer>(url: &Url, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&url.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Url, D::Error> {
        let as_string: &str = <(&str)>::deserialize(deserializer)?;
        as_string.parse().map_err(Error::custom)
    }
}

mod time_serde {
    use super::Time;
    use chrono::{TimeZone, Utc};

    use serde::ser::{Serializer};
    use serde::de::{Deserialize, Deserializer};

    pub fn serialize<S: Serializer>(time: &Time, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(time.timestamp())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Time, D::Error> {
        let as_timestamp: i64 = <i64>::deserialize(deserializer)?;
        Ok(Utc.timestamp(as_timestamp, 0))
    }
}

impl SerdeAssertionGrant {
    fn try_from(grant: &Grant) -> Result<Self, ()> {
        let mut public_extensions: HashMap<String, Option<String>> = HashMap::new();
        if let Some(_) = grant.extensions.iter_private().next() {
            return Err(())
        };
        for (name, content) in grant.extensions.iter_public() {
            public_extensions.insert(name.to_string(), content.map(str::to_string));
        }
        Ok(SerdeAssertionGrant {
            owner_id: grant.owner_id.clone(),
            client_id: grant.client_id.clone(),
            scope: grant.scope.clone(),
            redirect_uri: grant.redirect_uri.clone(),
            until: grant.until.clone(),
            public_extensions,
        })
    }

    fn grant(self) -> Grant {
        let mut extensions = Extensions::new();
        for (name, content) in self.public_extensions.into_iter() {
            extensions.set_raw(name, Extension::public(content))
        }
        Grant {
            owner_id: self.owner_id,
            client_id: self.client_id,
            scope: self.scope,
            redirect_uri: self.redirect_uri,
            until: self.until,
            extensions: extensions,
        }
    }
}
