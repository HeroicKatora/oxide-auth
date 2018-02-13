//! Generates bearer tokens and refresh tokens.
//!
//! Internally similar to the authorization module, tokens generated here live longer and can be
//! renewed. There exist two fundamental implementation as well, one utilizing in memory hash maps
//! while the other uses cryptographic signing.
use std::collections::HashMap;

use super::Time;
use super::grant::Grant;
use super::generator::{TokenGenerator, Assertion};

use ring::digest::SHA256;
use ring::pbkdf2::derive as key_derive;
use ring::hmac::SigningKey;

/// Issuers create bearer tokens.
///
/// It's the issuers decision whether a refresh token is offered or not. In any case, it is also
/// responsible for determining the validity and parameters of any possible token string. Some
/// backends or frontends may decide not to propagate the refresh token (for example because
/// they do not intend to offer a statefull refresh api).
pub trait Issuer {
    /// Create a token authorizing the request parameters
    fn issue(&mut self, Grant) -> Result<IssuedToken, ()>;

    /// Get the values corresponding to a bearer token
    fn recover_token<'a>(&'a self, &'a str) -> Option<Grant>;

    /// Get the values corresponding to a refresh token
    fn recover_refresh<'a>(&'a self, &'a str) -> Option<Grant>;
}

/// Token parameters returned to a client.
#[derive(Clone, Debug)]
pub struct IssuedToken {
    /// The bearer token
    pub token: String,

    /// The refresh token
    pub refresh: String,

    /// Expiration timestamp (Utc).
    ///
    /// Technically, a time to live is expected in the response but this will be transformed later.
    /// In a direct backend access situation, this enables high precision timestamps.
    pub until: Time,
}

/// Keeps track of access and refresh tokens by a hash-map.
///
/// The generator is itself trait based and can be chosen during construction. It is assumed to not
/// be possible for two different grants to generate the same token in the issuer.
pub struct TokenMap<G: TokenGenerator> {
    generator: G,
    access: HashMap<String, Grant>,
    refresh: HashMap<String, Grant>,
}

impl<G: TokenGenerator> TokenMap<G> {
    /// Construct a `TokenMap` from the given generator.
    pub fn new(generator: G) -> Self {
        Self {
            generator: generator,
            access: HashMap::new(),
            refresh: HashMap::new(),
        }
    }
}

impl<G: TokenGenerator> Issuer for TokenMap<G> {
    fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        let (token, refresh) = {
            let token = self.generator.generate(&grant)?;
            let refresh = self.generator.generate(&grant)?;
            (token, refresh)
        };

        let until = grant.until.clone();
        self.access.insert(token.clone(), grant.clone());
        self.refresh.insert(refresh.clone(), grant);
        Ok(IssuedToken { token, refresh, until })
    }

    fn recover_token<'a>(&'a self, token: &'a str) -> Option<Grant> {
        self.access.get(token).cloned()
    }

    fn recover_refresh<'a>(&'a self, token: &'a str) -> Option<Grant> {
        self.refresh.get(token).cloned()
    }
}

/// Signs grants instead of storing them.
///
/// Although this token instance allows preservation of memory, it also implies that tokens, once
/// issued, are harder to revoke.
pub struct TokenSigner {
    signer: Assertion,
}

impl TokenSigner {
    /// Construct a signing instance from a private signing key.
    pub fn new(key: SigningKey) -> TokenSigner {
        TokenSigner { signer: Assertion::new(key) }
    }

    /// Construct a signing instance from a passphrase, deriving a signing key in the process.
    ///
    /// The use of this function is DISCOURAGED.
    ///
    /// The salt SHOULD be changed to a self-generated one where possible instead of
    /// relying on the default one which was generated as 32 random bytes with openssl.
    /// However, at that point fully switching to private SigningKey instances is possibly
    /// a better option.
    pub fn new_from_passphrase(passwd: &str, salt: Option<&[u8]>) -> TokenSigner {
        // Default salt if none was provided, generated with `openssl rand 32`
        let salt = salt.unwrap_or(
            b"\xdf\xcf\xddt\n\xd08a*\xc3\x96\xafj<\x8c\xa7\xaa\x15\xce$\x83ND\xb4\xdf\x98%\xcb\xde\x1f\xf0\x9a"
        );

        let mut out = Vec::new();
        out.resize(SHA256.block_len, 0);

        key_derive(
            &SHA256,
            // ~32000 iterations, not quite the 10^6 of Lastpass but also more than 1ms on an i5
            2 << 16,
            salt,
            passwd.as_bytes(),
            out.as_mut_slice());
        let key = SigningKey::new(&SHA256, out.as_slice());

        TokenSigner { signer: Assertion::new(key) }
    }
}

impl Issuer for TokenSigner {
    fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        let token = self.signer.tag("token").generate(&grant)?;
        let refresh = self.signer.tag("refresh").generate(&grant)?;
        Ok(IssuedToken {token, refresh, until: grant.until})
    }

    fn recover_token<'a>(&'a self, token: &'a str) -> Option<Grant> {
        self.signer.tag("token").extract(token).ok()
    }

    fn recover_refresh<'a>(&'a self, token: &'a str) -> Option<Grant> {
        self.signer.tag("refresh").extract(token).ok()
    }
}

#[cfg(test)]
/// Tests for issuer implementations, including those provided here.
pub mod tests {
    use super::*;
    use primitives::grant::Extensions;
    use primitives::generator::RandomGenerator;
    use chrono::{Duration, Utc};

    /// Tests the simplest invariants that should be upheld by all authorizers.
    ///
    /// This create a token, without any extensions, an lets the issuer generate a issued token.
    /// The uri is `https://example.com` and the token lasts for an hour. Generation of a valid
    /// refresh token is not tested against.
    ///
    /// Custom implementations may want to import and use this in their own tests.
    pub fn simple_test_suite(issuer: &mut Issuer) {
        let request = Grant {
            client_id: "Client".to_string(),
            owner_id: "Owner".to_string(),
            redirect_uri: "https://example.com".parse().unwrap(),
            scope: "default".parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        };

        let issued = issuer.issue(request)
            .expect("Issuing failed");
        let from_token = issuer.recover_token(&issued.token)
            .expect("Could not recover the issued token");

        assert_eq!(from_token.client_id, "Client");
        assert_eq!(from_token.owner_id, "Owner");
        assert!(Utc::now() < from_token.until);
    }

    #[test]
    fn signer_test_suite() {
        let passwd = "Some secret password";
        let mut signer = TokenSigner::new_from_passphrase(passwd, None);
        simple_test_suite(&mut signer);
    }

    #[test]
    fn token_map_test_suite() {
        let mut token_map = TokenMap::new(RandomGenerator::new(16));
        simple_test_suite(&mut token_map);
    }
}
