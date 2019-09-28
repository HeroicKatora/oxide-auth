use chrono::{Duration, Utc};
use oxide_auth::primitives::{issuer::{IssuedToken, Issuer}, grant::Grant};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::generator::{Assertion, TaggedAssertion};

/// Signs grants instead of storing them.
///
/// Although this token instance allows preservation of memory it also implies that tokens, once
/// issued, are impossible to revoke.
pub struct TokenSigner {
    duration: Option<Duration>,
    signer: Assertion,
    // FIXME: make this an AtomicU64 once stable.
    counter: AtomicUsize,
    have_refresh: bool,
}

impl TokenSigner {
    /// Construct a signing instance from a private signing key.
    ///
    /// Security notice: Never use a password alone to construct the signing key. Instead, generate
    /// a new key using a utility such as `openssl rand` that you then store away securely.
    pub fn new(secret: Assertion) -> TokenSigner {
        TokenSigner { 
            duration: None,
            signer: secret,
            counter: AtomicUsize::new(0),
            have_refresh: false,
        }
    }

    /// Construct a signing instance whose tokens only live for the program execution.
    ///
    /// Useful for rapid prototyping where tokens need not be stored in a persistent database and
    /// can be invalidated at any time. This interface is provided with simplicity in mind, using
    /// the default system random generator (`ring::rand::SystemRandom`).
    pub fn ephemeral() -> TokenSigner {
        TokenSigner::new(Assertion::ephemeral())
    }

    /// Set the validity of all issued grants to the specified duration.
    ///
    /// This only affects tokens issued after this call. The default duration is 1 (ONE) hour for
    /// tokens issued for the authorization code grant method. For many users this may seem to
    /// short but should be secure-by-default. You may want to increase the duration, or instead
    /// use long lived refresh token instead (although you currently need to handle refresh tokens
    /// yourself, coming soonish).
    pub fn valid_for(&mut self, duration: Duration) {
        self.duration = Some(duration);
    }

    /// Set all grants to be valid for their default duration.
    ///
    /// This only affects tokens issued after this call. The default duration is 1 (ONE) hour for
    /// tokens issued for the authorization code grant method.
    pub fn valid_for_default(&mut self) {
        self.duration = None;
    }

    /// Determine whether to generate refresh tokens.
    ///
    /// By default, this option is *off*. Since the `TokenSigner` can on its own not revoke any
    /// tokens it should be considered carefullly whether to issue very long-living and powerful
    /// refresh tokens. On instance where this might be okay is as a component of a grander token
    /// architecture that adds a revocation mechanism.
    pub fn generate_refresh_tokens(&mut self, refresh: bool) {
        self.have_refresh = refresh;
    }

    /// Get the next counter value.
    fn next_counter(&self) -> usize {
        // Acquire+Release is overkill. We only need to ensure that each return value occurs at
        // most once. We would even be content with getting the counter out-of-order in a single
        // thread.
        self.counter.fetch_add(1, Ordering::Relaxed)
    }

    fn refreshable_token(&self, grant: &Grant) -> Result<IssuedToken, ()> {
        let first_ctr = self.next_counter() as u64;
        let second_ctr = self.next_counter() as u64;

        let token = self.as_token()
            .sign(first_ctr, grant)?;
        let refresh = self.as_refresh()
            .sign(second_ctr, grant)?;

        Ok(IssuedToken {
            token,
            refresh,
            until: grant.until,
        })
    }

    fn unrefreshable_token(&self, grant: &Grant) -> Result<IssuedToken, ()> {
        let counter = self.next_counter() as u64;

        let token = self.as_token()
            .sign(counter, grant)?;

        Ok(IssuedToken::without_refresh(token, grant.until))
    }

    fn as_token(&self) -> TaggedAssertion {
        self.signer.tag("token")
    }

    fn as_refresh(&self) -> TaggedAssertion {
        self.signer.tag("refresh")
    }
}

impl Issuer for TokenSigner {
    fn issue(&mut self, mut grant: Grant) -> Result<IssuedToken, ()> {
        if let Some(duration) = &self.duration {
            grant.until = Utc::now() + *duration;
        }

        if self.have_refresh {
            self.refreshable_token(&grant)
        } else {
            self.unrefreshable_token(&grant)
        }
    }

    fn recover_token<'t>(&'t mut self, token: &'t str) -> Result<Option<Grant>, ()> {
        Ok(self.as_token().extract(token).ok())
    }

    fn recover_refresh<'t>(&'t mut self, token: &'t str) -> Result<Option<Grant>, ()> {
        if !self.have_refresh {
            return Ok(None)
        }

        Ok(self.as_refresh().extract(token).ok())
    }
}

impl<'a> Issuer for &'a TokenSigner {
    fn issue(&mut self, mut grant: Grant) -> Result<IssuedToken, ()> {
        if let Some(duration) = &self.duration {
            grant.until = Utc::now() + *duration;
        }

        if self.have_refresh {
            self.refreshable_token(&grant)
        } else {
            self.unrefreshable_token(&grant)
        }
    }

    fn recover_token<'t>(&'t mut self, token: &'t str) -> Result<Option<Grant>, ()> {
        Ok(self.as_token().extract(token).ok())
    }

    fn recover_refresh<'t>(&'t mut self, token: &'t str) -> Result<Option<Grant>, ()> {
        if !self.have_refresh {
            return Ok(None)
        }

        Ok(self.as_refresh().extract(token).ok())
    }
}

#[cfg(test)]
/// Tests for issuer implementations, including those provided here.
pub mod tests {
    use super::*;
    use oxide_auth::primitives::{
        generator::TagGrant,
        grant::Extensions,
        issuer::TokenMap,
    };
    use chrono::{Duration, Utc};

    use crate::generator::RandomGenerator;

    fn grant_template() -> Grant {
        Grant {
            client_id: "Client".to_string(),
            owner_id: "Owner".to_string(),
            redirect_uri: "https://example.com".parse().unwrap(),
            scope: "default".parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        }
    }

    /// Tests the simplest invariants that should be upheld by all authorizers.
    ///
    /// This create a token, without any extensions, an lets the issuer generate a issued token.
    /// The uri is `https://example.com` and the token lasts for an hour except if overwritten.
    /// Generation of a valid refresh token is not tested against.
    ///
    /// Custom implementations may want to import and use this in their own tests.
    pub fn simple_test_suite(issuer: &mut dyn Issuer) {
        let request = grant_template();

        let issued = issuer.issue(request.clone())
            .expect("Issuing failed");
        let from_token = issuer.recover_token(&issued.token)
            .expect("Issuer failed during recover")
            .expect("Issued token appears to be invalid");

        assert_ne!(issued.token, issued.refresh);
        assert_eq!(from_token.client_id, "Client");
        assert_eq!(from_token.owner_id, "Owner");
        assert!(Utc::now() < from_token.until);

        let issued_2 = issuer.issue(request)
            .expect("Issuing failed");
        assert_ne!(issued.token, issued_2.token);
        assert_ne!(issued.token, issued_2.refresh);
        assert_ne!(issued.refresh, issued_2.refresh);
        assert_ne!(issued.refresh, issued_2.token);
    }

    #[test]
    fn signer_test_suite() {
        let mut signer = TokenSigner::ephemeral();
        // Refresh tokens must be unique if generated. If they are not even generated, they are
        // obviously not unique.
        signer.generate_refresh_tokens(true);
        simple_test_suite(&mut signer);
    }

    #[test]
    fn signer_no_default_refresh() {
        let mut signer = TokenSigner::ephemeral();
        let issued = signer.issue(grant_template());

        let token = issued.expect("Issuing without refresh token failed");
        assert!(!token.refreshable());
    }

    #[test]
    fn random_test_suite() {
        let mut token_map = TokenMap::new(RandomGenerator::new(16));
        simple_test_suite(&mut token_map);
    }

    #[test]
    fn random_has_refresh() {
        let mut token_map = TokenMap::new(RandomGenerator::new(16));
        let issued = token_map.issue(grant_template());

        let token = issued.expect("Issuing without refresh token failed");
        assert!(token.refreshable());
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
        let mut token_map = TokenMap::new(BadGenerator);
        simple_test_suite(&mut token_map);
    }
}
