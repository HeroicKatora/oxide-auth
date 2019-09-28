
#[cfg(test)]
/// Tests for authorizer implementations, including those provided here.
pub mod tests {
    use oxide_auth::primitives::{
        authorizer::*,
        generator::TagGrant,
        grant::{Grant, Extensions},
    };
    use chrono::Utc;

    use crate::generator::{Assertion, AssertionKind, RandomGenerator};

    /// Tests some invariants that should be upheld by all authorizers.
    ///
    /// Custom implementations may want to import and use this in their own tests.
    pub fn simple_test_suite(authorizer: &mut dyn Authorizer) {
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

        // Authorize the same token again.
        let token_again = authorizer.authorize(grant.clone())
            .expect("Authorization should not fail here");
        // We don't produce the same token twice.
        assert_ne!(token, token_again);
    }

    #[test]
    fn random_test_suite() {
        let mut storage = AuthMap::new(RandomGenerator::new(16));
        simple_test_suite(&mut storage);
    }

    #[test]
    fn signing_test_suite() {
        let assertion = Assertion::new(
            AssertionKind::HmacSha256, 
            b"7EGgy8zManReq9l/ez0AyYE+xPpcTbssgW+8gBnIv3s=");
        let mut storage = AuthMap::new(assertion);
        simple_test_suite(&mut storage);
    }

    #[test]
    #[should_panic]
    fn bad_generator() {
        struct BadGenerator;
        impl TagGrant for BadGenerator {
            fn tag(&mut self, _: u64, _: &Grant) -> Result<String, ()> {
                Ok("YOLO.HowBadCanItBeToRepeatTokens?".into())
            }
        }

        let mut storage = AuthMap::new(BadGenerator);
        simple_test_suite(&mut storage);
    }
}
