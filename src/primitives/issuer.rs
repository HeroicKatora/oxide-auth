//! Generates bearer tokens and refresh tokens.
//!
//! Internally similar to the authorization module, tokens generated here live longer and can be
//! renewed. There exist two fundamental implementation as well, one utilizing in memory hash maps
//! while the other uses cryptographic signing.
use std::collections::HashMap;
use std::clone::Clone;
use std::borrow::Cow;
use chrono::{Utc, Duration};
use super::Time;
use super::grant::{Grant, GrantRef, GrantRequest};
use super::generator::{TokenGenerator, Assertion};
use ring::digest::SHA256;
use ring::hkdf::extract_and_expand;
use ring::hmac::SigningKey;

/// Issuers create bearer tokens.
///
/// It's the issuers decision whether a refresh token is offered or not. In any case, it is also
/// responsible for determining the validity and parameters of any possible token string. Some
/// backends or frontends may decide not to propagate the refresh token (for example because
/// they do not intend to offer a statefull refresh api).
pub trait Issuer {
    /// Create a token authorizing the request parameters
    fn issue(&mut self, GrantRequest) -> IssuedToken;

    /// Get the values corresponding to a bearer token
    fn recover_token<'a>(&'a self, &'a str) -> Option<GrantRef<'a>>;

    /// Get the values corresponding to a refresh token
    fn recover_refresh<'a>(&'a self, &'a str) -> Option<GrantRef<'a>>;
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
    fn issue(&mut self, req: GrantRequest) -> IssuedToken {
        let grant = Grant {
            owner_id: req.owner_id.to_string(),
            client_id: req.client_id.to_string(),
            scope: req.scope.clone(),
            redirect_uri: req.redirect_uri.clone(),
            until: Utc::now() + Duration::hours(1),
        };
        let (token, refresh) = {
            let generator_grant = (&grant).into();
            let token = self.generator.generate(&generator_grant);
            let refresh = self.generator.generate(&generator_grant);
            (token, refresh)
        };
        let until = grant.until.clone();
        self.access.insert(token.clone(), grant.clone());
        self.refresh.insert(refresh.clone(), grant);
        IssuedToken { token, refresh, until }
    }

    fn recover_token<'a>(&'a self, token: &'a str) -> Option<GrantRef<'a>> {
        self.access.get(token).map(|v| v.into())
    }

    fn recover_refresh<'a>(&'a self, token: &'a str) -> Option<GrantRef<'a>> {
        self.refresh.get(token).map(|v| v.into())
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
    /// The salting_key SHOULD be changed to a self-generated one where possible instead of
    /// relying on the default key. However, at that point fully switching to private
    /// SigningKey instances is possibly a better option.
    pub fn new_from_passphrase(passwd: &str, salting_key: Option<SigningKey>) -> TokenSigner {
        // Default salt if none was provided, generated with `openssl rand 32`
        let salting_key = salting_key.unwrap_or_else(|| {
            let default = b"\xdf\xcf\xddt\n\xd08a*\xc3\x96\xafj<\x8c\xa7\xaa\x15\xce$\x83ND\xb4\xdf\x98%\xcb\xde\x1f\xf0\x9a";
            SigningKey::new(&SHA256, default)
        });

        let mut out = Vec::new();
        out.resize(SHA256.block_len, 0);

        extract_and_expand(
            &salting_key,
            passwd.as_bytes(),
            b"oxide-auth-token-signer",
            out.as_mut_slice());
        let key = SigningKey::new(&SHA256, out.as_slice());

        TokenSigner { signer: Assertion::new(key) }
    }
}

impl Issuer for TokenSigner {
    fn issue(&mut self, req: GrantRequest) -> IssuedToken {
        let grant = GrantRef {
            owner_id: req.owner_id.into(),
            client_id: req.client_id.into(),
            scope: Cow::Borrowed(req.scope),
            redirect_uri: Cow::Borrowed(req.redirect_uri),
            until: Cow::Owned(Utc::now() + Duration::hours(1)),
        };
        let token = self.signer.tag("token").generate(&grant);
        let refresh = self.signer.tag("refresh").generate(&grant);
        IssuedToken {token, refresh, until: grant.until.into_owned() }
    }

    fn recover_token<'a>(&'a self, token: &'a str) -> Option<GrantRef<'a>> {
        self.signer.tag("token").extract(token).ok()
    }

    fn recover_refresh<'a>(&'a self, token: &'a str) -> Option<GrantRef<'a>> {
        self.signer.tag("refresh").extract(token).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_signer_roundtrip() {
        let passwd = "Some secret password";
        let mut issuer = TokenSigner::new_from_passphrase(passwd, None);
        let request = GrantRequest {
            client_id: "Client".into(),
            owner_id: "Owner".into(),
            redirect_uri: &"https://example.com".parse().unwrap(),
            scope: &"default".parse().unwrap(),
        };

        let issued = issuer.issue(request);
        assert!(Utc::now() < issued.until);

        let from_token = issuer.recover_token(&issued.token).unwrap();
        assert_eq!(from_token.client_id, "Client");
        assert_eq!(from_token.owner_id, "Owner");
        assert!(Utc::now() < *from_token.until.as_ref());
    }
}
