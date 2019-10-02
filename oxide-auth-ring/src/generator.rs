use oxide_auth::primitives::{
    grant::Grant,
    generator::{SerdeAssertionGrant, TagGrant},
    issuer::{Tagged, Signer},
};

use ring::digest::SHA256;
use ring::rand::{SystemRandom, SecureRandom};
use ring::hmac::SigningKey;

use base64::{encode, decode};
use rmp_serde;
use serde_derive::{Deserialize, Serialize};

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
///
/// The actual generator is given by a `TaggedAssertion` from `Assertion::tag` which enables
/// signing the same grant for different uses, i.e. separating authorization from bearer grants and
/// refresh tokens.
pub struct Assertion {
    secret: SigningKey,
}

/// Binds a tag to the data. The signature will be unique for data as well as the tag.
pub struct TaggedAssertion<'a>(&'a Assertion, &'a str);

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

impl<'a> Tagged<'a> for Assertion {
    type Signer = TaggedAssertion<'a>;

    fn tag(&'a self, tag: &'a str) -> Self::Signer {
        TaggedAssertion(self, tag)
    }
}

impl<'a> Signer for TaggedAssertion<'a> {
    fn sign(&self, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.0.generate_tagged(counter, grant, self.1)
    }

    fn extract(&self, token: &str) -> Result<Grant, ()> {
        self.0.extract(token).and_then(|(token, tag)| {
            if tag == self.1 {
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

impl Default for Assertion {
    fn default() -> Self {
        Self::ephemeral()
    }
}
