//! Generators produce string code grant and bearer tokens for a determined grant.
//!
//! In short, a code grant needs to encapsulate information about the owner, client, redirect_uri,
//! scope, and lifetime of a grant. This information needs to be uniquely recoverable.
//!
//! Three major implementation exists:
//!     - `RandomGenerator` and `RandGenerator` depend on the entropy of the generated token to make guessing
//!     infeasible. `RandGenerator` is provided by default, while `RandomGenerator` is in the -ring
//!     crate
//!     - `Assertion` cryptographically verifies the integrity of a token, trading security without
//!     persistent storage for the loss of revocability. It is thus unfit for some backends, which
//!     is not currently expressed in the type system or with traits. It can be found in the -ring
//!     crate
use super::grant::Grant;

use rand::{Rng, SeedableRng, rngs::StdRng};

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

/// An implementation of TagGrant backed by a cryptographically secure source of randomness
pub struct RandGenerator {
    rand: StdRng,
    len: usize,
}

impl RandGenerator {
    /// Create a new RandGenerator from a CryptoRng type and the length of tags that will be
    /// generated
    pub fn new(len: usize) -> Self {
        RandGenerator {
            rand: StdRng::from_entropy(),
            len,
        }
    }

    fn generate(&mut self) -> Result<String, ()> {
        let mut result = vec![0; self.len];
        self.rand.try_fill(result.as_mut_slice()).map_err(|_| ())?;
        Ok(base64::encode(&result))
    }
}

impl TagGrant for RandGenerator {
    fn tag(&mut self, _: u64, _: &Grant) -> Result<String, ()> {
        self.generate()
    }
}

impl<'a, T: TagGrant + ?Sized + 'a> TagGrant for Box<T> {
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        (&mut **self).tag(counter, grant)
    }
}

impl<'a, T: TagGrant + ?Sized + 'a> TagGrant for &'a mut T {
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        (&mut **self).tag(counter, grant)
    }
}

#[cfg(test)]
mod tests {
    use crate::primitives::grant::Grant;
    use super::{RandGenerator, TagGrant};

    fn build_grant() -> Grant {
        Grant {
            owner_id: String::from("hi"),
            client_id: String::from("hello"),
            scope: "read".parse().unwrap(),
            redirect_uri: "https://example.com/".parse().unwrap(),
            until: chrono::Utc::now(),
            extensions: Default::default(),
        }
    }

    #[test]
    fn assert_send_sync_static_rand() {
        fn uses<T: Send + Sync + 'static>(_: T) {}
        let _ = uses(RandGenerator::new(16));
    }

    #[test]
    fn assert_generators_work() {
        assert!(RandGenerator::new(16).tag(64, &build_grant()).is_ok());
    }
}
