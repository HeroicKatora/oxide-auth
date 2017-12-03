//! Generates bearer tokens and refresh tokens.
//!
//! Internally similar to the authorization module, tokens generated here live longer and can be
//! renewed [WIP].
use std::collections::HashMap;
use std::clone::Clone;
use std::borrow::Cow;
use chrono::{Utc, Duration};
use super::{Request, IssuedToken};
use super::grant::{Grant, GrantRef};
use super::generator::{TokenGenerator, Assertion};
use ring::digest::SHA256;
use ring::hmac::SigningKey;

/// Issuers create bearer tokens.
///
/// It's the issuers decision whether a refresh token is offered or not. In any case, it is also
/// responsible for determining the validity and parameters of any possible token string. Some
/// backends or frontends may decide not to propagate the refresh token (for example because
/// they do not intend to offer a statefull refresh api).
pub trait Issuer {
    /// Create a token authorizing the request parameters
    fn issue(&mut self, Request) -> IssuedToken;
    /// Get the values corresponding to a bearer token
    fn recover_token<'a>(&'a self, &'a str) -> Option<GrantRef<'a>>;
    /// Get the values corresponding to a refresh token
    fn recover_refresh<'a>(&'a self, &'a str) -> Option<GrantRef<'a>>;
}

pub struct TokenMap<G: TokenGenerator> {
    generator: G,
    access: HashMap<String, Grant>,
    refresh: HashMap<String, Grant>,
}

impl<G: TokenGenerator> TokenMap<G> {
    pub fn new(generator: G) -> Self {
        Self {
            generator: generator,
            access: HashMap::new(),
            refresh: HashMap::new(),
        }
    }
}

impl<G: TokenGenerator> Issuer for TokenMap<G> {
    fn issue(&mut self, req: Request) -> IssuedToken {
        let grant = Grant {
            owner_id: req.owner_id.to_string(),
            client_id: req.client_id.to_string(),
            scope: req.scope.clone(),
            redirect_url: req.redirect_url.clone(),
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

pub struct TokenSigner {
    signer: Assertion,
}

impl TokenSigner {
    pub fn new(key: SigningKey) -> TokenSigner {
        TokenSigner { signer: Assertion::new(key) }
    }

    pub fn new_from_passphrase(passwd: &str) -> TokenSigner {
        let key = SigningKey::new(&SHA256, passwd.as_bytes());
        TokenSigner { signer: Assertion::new(key) }
    }
}

impl Issuer for TokenSigner {
    fn issue(&mut self, req: Request) -> IssuedToken {
        let grant = GrantRef {
            owner_id: req.owner_id.into(),
            client_id: req.client_id.into(),
            scope: Cow::Borrowed(req.scope),
            redirect_url: Cow::Borrowed(req.redirect_url),
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
        let mut issuer = TokenSigner::new_from_passphrase(passwd);
        let request = Request {
            client_id: "Client".into(),
            owner_id: "Owner".into(),
            redirect_url: &"https://example.com".parse().unwrap(),
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
