use oxide_auth::primitives::{
    grant::{Value, Grant, Extensions},
    generator::TagGrant,
    issuer::Signer,
    scope::Scope,
};

use ring::digest::SHA256;
use ring::rand::{SystemRandom, SecureRandom};
use ring::hmac::SigningKey;

use std:: collections::HashMap;

use base64::{encode, decode};
use rmp_serde;
use serde_derive::{Deserialize, Serialize};
use url::Url;

type Time = chrono::DateTime<chrono::Utc>;

/// Generates tokens from random bytes.
///
/// Each byte is chosen randomly from the basic `rand::thread_rng`. This generator will always
/// succeed.
pub struct RandomGenerator {
    random: SystemRandom,
    len: usize
}

/// Generates tokens by signing its specifics with a private key.
///
/// Tokens produced by the generator include a serialized version of the grant followed by an HMAC
/// signature.  Since data is not encrypted, this token generator will ERROR if any private
/// extension is present in the grant.
pub struct Assertion {
    secret: SigningKey,
}

/// The cryptographic suite ensuring integrity of tokens.
pub enum AssertionKind {
    /// Uses [HMAC (RFC 2104)][HMAC] with [SHA-256 (FIPS 180-4)][SHA256] hash.
    ///
    /// [HMAC]: https://tools.ietf.org/html/rfc2104
    /// [SHA256]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    HmacSha256,
    #[doc(hidden)]
    __NonExhaustive,
}

#[derive(Deserialize, Serialize)]
struct AssertGrant(Vec<u8>, Vec<u8>);

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

impl RandomGenerator {
    /// Generates tokens with a specific byte length.
    pub fn new(length: usize) -> RandomGenerator {
        RandomGenerator {
            random: SystemRandom::new(),
            len: length
        }
    }

    fn generate(&self) -> String {
        let mut result = vec![0; self.len];
        self.random.fill(result.as_mut_slice())
            .expect("Failed to generate random token");
        encode(&result)
    }
}

impl Assertion {
    /// Construct an assertion from a custom secret.
    ///
    /// If the key material mismatches the key length required by the selected hash algorithm then
    /// padding or shortening of the supplied key material may be applied in the form dictated by
    /// the signature type. See the respective standards.
    ///
    /// If future suites are added where this is not possible, his function may panic when supplied
    /// with an incorrect key length.
    pub fn new(kind: AssertionKind, key: &[u8]) -> Self {
        let key = match kind {
            AssertionKind::HmacSha256 => SigningKey::new(&SHA256, key),
            AssertionKind::__NonExhaustive => unreachable!(),
        };

        Assertion {
            secret: key,
        }
    }

    /// Construct an assertion instance whose tokens are only valid for the program execution.
    #[deprecated = "Use the correctly named `ephemeral` instead."]
    #[doc(hidden)]
    pub fn ephermal() -> Assertion {
        Self::ephemeral()
    }

    /// Construct an assertion instance whose tokens are only valid for the program execution.
    pub fn ephemeral() -> Self {
        Assertion {
            secret: SigningKey::generate(&SHA256, &SystemRandom::new()).unwrap(),
        }
    }

    fn extract<'a>(&self, token: &'a str) -> Result<(Grant, String), ()> {
        let decoded = decode(token).map_err(|_| ())?;
        let assertion: AssertGrant = rmp_serde::from_slice(&decoded).map_err(|_| ())?;
        ring::hmac::verify_with_own_key(&self.secret, &assertion.0, &assertion.1).map_err(|_| ())?;
        let (_, serde_grant, tag): (u64, SerdeAssertionGrant, String)
            = rmp_serde::from_slice(&assertion.0).map_err(|_| ())?;
        Ok((serde_grant.grant(), tag))
    }

    fn signature(&self, data: &[u8]) -> ring::hmac::Signature {
        ring::hmac::sign(&self.secret, data)
    }

    fn counted_signature(&self, counter: u64, grant: &Grant) 
        -> Result<String, ()>
    {
        let serde_grant = SerdeAssertionGrant::try_from(grant)?;
        let tosign = rmp_serde::to_vec(&(serde_grant, counter)).unwrap();
        let signature = self.signature(&tosign);
        Ok(base64::encode(&signature))
    }

    fn generate_tagged(&self, counter: u64, grant: &Grant, tag: &str) -> Result<String, ()> {
        let serde_grant = SerdeAssertionGrant::try_from(grant)?;
        let tosign = rmp_serde::to_vec(&(counter, serde_grant, tag)).unwrap();
        let signature = self.signature(&tosign);
        Ok(encode(&rmp_serde::to_vec(&AssertGrant(tosign, signature.as_ref().to_vec())).unwrap()))
    }
}

impl Signer for Assertion {
    fn sign(&self, tag: &str, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.generate_tagged(counter, grant, tag)
    }

    fn extract(&self, tag: &str, token: &str) -> Result<Grant, ()> {
        self.extract(token).and_then(|(token, extracted_tag)| {
            if extracted_tag == tag {
                Ok(token)
            } else {
                Err(())
            }
        })
    }
}

impl TagGrant for RandomGenerator {
    fn tag(&mut self, _: u64, _: &Grant) -> Result<String, ()> {
        Ok(self.generate())
    }
}

impl<'a> TagGrant for &'a RandomGenerator {
    fn tag(&mut self, _: u64, _: &Grant) -> Result<String, ()> {
        Ok(self.generate())
    }
}

impl TagGrant for Assertion {
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.counted_signature(counter, grant)
    }
}

impl<'a> TagGrant for &'a Assertion {
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.counted_signature(counter, grant)
    }
}

mod scope_serde {
    use oxide_auth::primitives::scope::Scope;

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

        if grant.extensions.private().any(|_| true) {
            return Err(())
        }

        for (name, content) in grant.extensions.public() {
            public_extensions.insert(name.to_string(), content.map(str::to_string));
        }

        Ok(SerdeAssertionGrant {
            owner_id: grant.owner_id.clone(),
            client_id: grant.client_id.clone(),
            scope: grant.scope.clone(),
            redirect_uri: grant.redirect_uri.clone(),
            until: grant.until,
            public_extensions,
        })
    }

    fn grant(self) -> Grant {
        let mut extensions = Extensions::new();
        for (name, content) in self.public_extensions.into_iter() {
            extensions.set_raw(name, Value::public(content))
        }
        Grant {
            owner_id: self.owner_id,
            client_id: self.client_id,
            scope: self.scope,
            redirect_uri: self.redirect_uri,
            until: self.until,
            extensions,
        }
    }
}

impl Default for Assertion {
    fn default() -> Self {
        Self::ephemeral()
    }
}
