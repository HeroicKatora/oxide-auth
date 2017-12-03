//! Generators produce string code grant and bearer tokens for a determined grant.
//!
//! In short, a code grant needs to encapsulate information about the owner, client, redirect_url,
//! scope, and lifetime of a grant. This information needs to be uniquely recoverable.
//!
//! Two major implementation exists:
//!     - `RandomGenerator` depends on the entropy of the generated token to make guessing
//!     infeasible.
//!     - `Assertion` cryptographically verifies the integrity of a token, trading security without
//!     persistent storage for the loss of revocability. It is thus unfit for some backends, which
//!     is not currently expressed in the type system or with traits.
use super::Grant;
use chrono::{Utc, TimeZone};
use std::borrow::Cow;
use rand::{thread_rng, Rng};
use ring;
use rmp_serde;
use url::Url;
use base64::{encode, decode};

/// Generic token for a specific grant.
///
/// The interface may be reused for authentication codes, bearer tokens and refresh tokens.
pub trait TokenGenerator {
    /// For example sign a grant or generate a random token. The exact guarantees and uses depend
    /// on the specific implementation.
    fn generate(&self, &Grant) -> String;
}

pub struct RandomGenerator {
    len: usize
}

impl RandomGenerator {
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

pub struct Assertion {
    secret: ring::hmac::SigningKey,
}

#[derive(Serialize, Deserialize)]
pub struct InternalAssertionGrant<'a>(&'a str, &'a str, &'a str, &'a str, (i64, u32), &'a str);
#[derive(Serialize, Deserialize)]
pub struct AssertGrant(Vec<u8>, Vec<u8>);

pub struct TaggedAssertion<'a>(&'a Assertion, &'a str);

impl Assertion {
    pub fn new(key: ring::hmac::SigningKey) -> Assertion {
        Assertion { secret: key}
    }

    pub fn tag<'a>(&'a self, tag: &'a str) -> TaggedAssertion<'a> {
        TaggedAssertion(self, tag)
    }

    fn extract<'a>(&self, token: &'a str) -> Result<(Grant<'a>, String), ()> {
        let readbytes = decode(token).map_err(|_| ())?;
        let AssertGrant(message, digest) = rmp_serde::from_slice(&readbytes).unwrap();

        ring::hmac::verify_with_own_key(&self.secret, &message, &digest).map_err(|_| ())?;
        let InternalAssertionGrant(owner_id, client_id, redirectbytes, scope, (ts, tsnanos), tag) =
            rmp_serde::from_slice(&message).map_err(|_| ())?;

        let redirect_url = Url::parse(redirectbytes).map_err(|_| ())?;
        let scope = scope.parse().map_err(|_| ())?;
        let until = Utc::timestamp(&Utc, ts, tsnanos);
        Ok((Grant{
            owner_id: Cow::Owned(owner_id.to_string()),
            client_id: Cow::Owned(client_id.to_string()),
            redirect_url: Cow::Owned(redirect_url),
            scope: Cow::Owned(scope),
            until: Cow::Owned(until),
        }, tag.to_string()))
    }

    fn generate_tagged(&self, grant: &Grant, tag: &str) -> String {
        let tosign = rmp_serde::to_vec(&InternalAssertionGrant(
            &grant.owner_id,
            &grant.client_id,
            grant.redirect_url.as_str(),
            &grant.scope.to_string(),
            (grant.until.timestamp(), grant.until.timestamp_subsec_nanos()),
            tag)).unwrap();
        let signature = ring::hmac::sign(&self.secret, &tosign);
        encode(&rmp_serde::to_vec(&AssertGrant(tosign, signature.as_ref().to_vec())).unwrap())
    }
}

impl<'a> TaggedAssertion<'a> {
    pub fn extract<'b>(&self, token: &'b str) -> Result<Grant<'b>, ()> {
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
