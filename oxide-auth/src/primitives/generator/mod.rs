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

use super::grant::Grant;

use std::rc::Rc;
use std::sync::Arc;

use base64::encode;
use rand::{rngs::OsRng, RngCore};

#[cfg(feature = "assertion-grant")]
pub use self::assertion_grant::{Assertion, AssertionKind, TaggedAssertion};

#[cfg(feature = "assertion-grant")]
mod assertion_grant;

/// Generic token for a specific grant.
///
/// The interface may be reused for authentication codes, bearer tokens and refresh tokens.
///
/// ## Requirements on implementations
///
/// When queried without repetition (users will change the `usage` counter each time), this
/// method MUST be indistinguishable from a random function. This should be the crypgraphic
/// requirements for signature schemes without requiring the verification property (the
/// function need no be deterministic). This enables two popular choices: actual signature
/// schemes and (pseudo-)random generators that ignore all input.
///
/// The requirement is derived from the fact that one should not be able to derive the tag for
/// another token from ones own. Since there may be multiple tokens for a grant, the `usage`
/// counter makes it possible for `Authorizer` and `Issuer` implementations to differentiate
/// between these.
pub trait TagGrant {
    /// For example sign the input parameters or generate a random token.
    fn tag(&mut self, usage: u64, grant: &Grant) -> Result<String, ()>;
}

/// Generates tokens from random bytes.
///
/// Each byte is chosen randomly from the basic `rand::thread_rng`. This generator will always
/// succeed.
pub struct RandomGenerator {
    random: OsRng,
    len: usize,
}

impl RandomGenerator {
    /// Generates tokens with a specific byte length.
    pub fn new(length: usize) -> RandomGenerator {
        RandomGenerator {
            random: OsRng {},
            len: length,
        }
    }

    fn generate(&self) -> String {
        let mut result = vec![0; self.len];
        let mut rnd = self.random;
        rnd.try_fill_bytes(result.as_mut_slice())
            .expect("Failed to generate random token");
        encode(&result)
    }
}

impl<'a, T: TagGrant + ?Sized + 'a> TagGrant for Box<T> {
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.tag(counter, grant)
    }
}

impl<'a, T: TagGrant + ?Sized + 'a> TagGrant for &'a mut T {
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.tag(counter, grant)
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

impl TagGrant for Rc<RandomGenerator> {
    fn tag(&mut self, _: u64, _: &Grant) -> Result<String, ()> {
        Ok(self.generate())
    }
}

impl TagGrant for Arc<RandomGenerator> {
    fn tag(&mut self, _: u64, _: &Grant) -> Result<String, ()> {
        Ok(self.generate())
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    #[allow(dead_code, unused)]
    #[cfg(feature = "assertion-grant")]
    fn assert_send_sync_static() {
        fn uses<T: Send + Sync + 'static>(arg: T) {}
        let _ = uses(RandomGenerator::new(16));
        let fake_key = [0u8; 16];
        let _ = uses(Assertion::new(AssertionKind::HmacSha256, &fake_key));
    }
}
