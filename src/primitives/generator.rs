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
use super::grant::{Extensions, Grant};

use base64::{encode, decode};
use chrono::{Utc, TimeZone};
use rand::{thread_rng, Rng};
use ring;
use rmp_serde;
use url::Url;

/// Generic token for a specific grant.
///
/// The interface may be reused for authentication codes, bearer tokens and refresh tokens.
pub trait TokenGenerator {
    /// For example sign a grant or generate a random token. The exact guarantees and uses depend
    /// on the specific implementation.
    fn generate(&self, &Grant) -> String;
}

/// Generates tokens from random bytes.
///
/// Each byte is chosen randomly from the basic `rand::thread_rng`.
pub struct RandomGenerator {
    len: usize
}

impl RandomGenerator {
    /// Generates tokens with a specific byte length.
    pub fn new(length: usize) -> RandomGenerator {
        RandomGenerator {len: length}
    }
}

impl TokenGenerator for RandomGenerator {
    fn generate(&self, _grant: &Grant) -> String {
        let result = thread_rng().gen_iter::<u8>().take(self.len).collect::<Vec<u8>>();
        encode(&result)
    }
}

/// Generates tokens by signing its specifics with a private key.
///
/// The actual generator is given by a `TaggedAssertion` from `Assertion::tag` which enables
/// signing the same grant for different uses, i.e. separating authorization from bearer grants and
/// refresh tokens.
pub struct Assertion {
    secret: ring::hmac::SigningKey,
}

#[derive(Serialize, Deserialize)]
struct InternalAssertionGrant<'a>(&'a str, &'a str, &'a str, &'a str, (i64, u32), &'a str);
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
        let readbytes = decode(token).map_err(|_| ())?;
        let AssertGrant(message, digest) = rmp_serde::from_slice(&readbytes).unwrap();

        ring::hmac::verify_with_own_key(&self.secret, &message, &digest).map_err(|_| ())?;
        let InternalAssertionGrant(owner_id, client_id, redirectbytes, scope, (ts, tsnanos), tag) =
            rmp_serde::from_slice(&message).map_err(|_| ())?;

        let redirect_uri = Url::parse(redirectbytes).map_err(|_| ())?;
        let scope = scope.parse().map_err(|_| ())?;
        let until = Utc::timestamp(&Utc, ts, tsnanos);
        Ok((Grant {
            owner_id: owner_id.to_string(),
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri,
            scope: scope,
            until: until,
            // FIXME: save and recover extensions with crypto
            extensions: Extensions::new(),
        }, tag.to_string()))
    }

    fn generate_tagged(&self, grant: &Grant, tag: &str) -> String {
        let tosign = rmp_serde::to_vec(&InternalAssertionGrant(
            &grant.owner_id,
            &grant.client_id,
            grant.redirect_uri.as_str(),
            &grant.scope.to_string(),
            (grant.until.timestamp(), grant.until.timestamp_subsec_nanos()),
            tag)).unwrap();
        let signature = ring::hmac::sign(&self.secret, &tosign);
        encode(&rmp_serde::to_vec(&AssertGrant(tosign, signature.as_ref().to_vec())).unwrap())
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
    fn generate(&self, grant: &Grant) -> String {
        self.0.generate_tagged(grant, self.1)
    }
}
