//! Authorizers are need to swap code grants for bearer tokens.
//!
//! The role of an authorizer is the ensure the consistency and security of request in which a
//! client is willing to trade a code grant for a bearer token. As such, it will first issue grants
//! to client according to parameters given by the resource owner and the registrar. Upon a client
//! side request, it will then check the given parameters to determine the authorization of such
//! clients.
use std::collections::HashMap;
use std::sync::{MutexGuard, RwLockWriteGuard};

use super::grant::Grant;
use super::generator::TokenGenerator;

/// Authorizers create and manage authorization codes.
///
/// The authorization code can be traded for a bearer token at the token endpoint.
pub trait Authorizer {
    /// Create a code which allows retrieval of a bearer token at a later time.
    fn authorize(&mut self, Grant) -> Result<String, ()>;

    /// Retrieve the parameters associated with a token, invalidating the code in the process. In
    /// particular, a code should not be usable twice (there is no stateless implementation of an
    /// authorizer for this reason).
    fn extract(&mut self, token: &str) -> Result<Option<Grant>, ()>;
}

/// An in-memory hash map.
///
/// This authorizer saves a mapping of generated strings to their associated grants. The generator
/// is itself trait based and can be chosen during construction. It is assumed to not be possible
/// for two different grants to generate the same token in the issuer.
pub struct AuthMap<I: TokenGenerator> {
    issuer: I,
    tokens: HashMap<String, Grant>
}


impl<I: TokenGenerator> AuthMap<I> {
    /// Create a hash map authorizer with the given issuer as a backend.
    pub fn new(issuer: I) -> Self {
        AuthMap {
            issuer: issuer,
            tokens: HashMap::new(),
        }
    }
}

impl<'a, A: Authorizer + ?Sized> Authorizer for &'a mut A {
    fn authorize(&mut self, grant: Grant) -> Result<String, ()> {
        (**self).authorize(grant)
    }

    fn extract(&mut self, code: &str) -> Result<Option<Grant>, ()> {
        (**self).extract(code)
    }
}

impl<A: Authorizer + ?Sized> Authorizer for Box<A> {
    fn authorize(&mut self, grant: Grant) -> Result<String, ()> {
        (**self).authorize(grant)
    }

    fn extract(&mut self, code: &str) -> Result<Option<Grant>, ()> {
        (**self).extract(code)
    }
}

impl<'a, A: Authorizer + ?Sized> Authorizer for MutexGuard<'a, A> {
    fn authorize(&mut self, grant: Grant) -> Result<String, ()> {
        (**self).authorize(grant)
    }

    fn extract(&mut self, code: &str) -> Result<Option<Grant>, ()> {
        (**self).extract(code)
    }
}

impl<'a, A: Authorizer + ?Sized> Authorizer for RwLockWriteGuard<'a, A> {
    fn authorize(&mut self, grant: Grant) -> Result<String, ()> {
        (**self).authorize(grant)
    }

    fn extract(&mut self, code: &str) -> Result<Option<Grant>, ()> {
        (**self).extract(code)
    }
}

impl<I: TokenGenerator> Authorizer for AuthMap<I> {
    fn authorize(&mut self, grant: Grant) -> Result<String, ()> {
        let token = self.issuer.generate(&grant)?;
        self.tokens.insert(token.clone(), grant);
        Ok(token)
    }

    fn extract<'a>(&mut self, grant: &'a str) -> Result<Option<Grant>, ()> {
        Ok(self.tokens.remove(grant))
    }
}

#[cfg(test)]
/// Tests for authorizer implementations, including those provided here.
pub mod tests {
    use super::*;
    use chrono::Utc;
    use primitives::grant::Extensions;

    /// Tests some invariants that should be upheld by all authorizers.
    ///
    /// Custom implementations may want to import and use this in their own tests.
    pub fn simple_test_suite(authorizer: &mut Authorizer) {
        let grant = Grant {
            owner_id: "Owner".to_string(),
            client_id: "Client".to_string(),
            scope: "One two three scopes".parse().unwrap(),
            redirect_uri: "https://example.com/redirect_me".parse().unwrap(),
            until: Utc::now(),
            extensions: Extensions::new(),
        };

        let token = authorizer.authorize(grant.clone())
            .expect("Authorization should not fail here");
        let recovered_grant = authorizer.extract(&token)
            .expect("Primitive failed extracting grant")
            .expect("Could not extract grant for valid token");

        if grant != recovered_grant {
            panic!("Grant was not stored correctly");
        }

        if authorizer.extract(&token).unwrap().is_some() {
            panic!("Token must only be usable once");
        }
    }

    #[test]
    fn test_storage() {
        use primitives::generator::{Assertion, RandomGenerator};
        use ring::hmac::SigningKey;
        use ring::digest::SHA256;

        let mut storage = AuthMap::new(RandomGenerator::new(16));
        simple_test_suite(&mut storage);

        let assertion_token_instance = Assertion::new(
            SigningKey::new(&SHA256, b"7EGgy8zManReq9l/ez0AyYE+xPpcTbssgW+8gBnIv3s="));
        let mut storage = AuthMap::new(assertion_token_instance.tag("authorizer"));
        simple_test_suite(&mut storage);
    }
}
