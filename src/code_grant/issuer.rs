use std::collections::HashMap;
use std::clone::Clone;
use std::borrow::Cow;
use chrono::{Utc, Duration};
use super::{Issuer, Grant, Request, Scope, Time, TokenGenerator, Url, IssuedToken};
use super::generator::Assertion;
use ring::digest::SHA256;
use ring::hmac::SigningKey;

#[derive(Clone)]
struct SpecificGrant {
    owner_id: String,
    client_id: String,
    scope: Scope,
    redirect_url: Url,
    until: Time
}

impl<'a> Into<Grant<'a>> for &'a SpecificGrant {
    fn into(self) -> Grant<'a> {
        Grant {
            owner_id: Cow::Borrowed(&self.owner_id),
            client_id: Cow::Borrowed(&self.client_id),
            scope: Cow::Borrowed(&self.scope),
            redirect_url: Cow::Borrowed(&self.redirect_url),
            until: Cow::Borrowed(&self.until),
        }
    }
}

pub struct TokenMap<G: TokenGenerator> {
    generator: G,
    access: HashMap<String, SpecificGrant>,
    refresh: HashMap<String, SpecificGrant>,
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
        let grant = SpecificGrant {
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

    fn recover_token<'a>(&'a self, token: &'a str) -> Option<Grant<'a>> {
        self.access.get(token).map(|v| v.into())
    }

    fn recover_refresh<'a>(&'a self, token: &'a str) -> Option<Grant<'a>> {
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
        let grant = Grant {
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

    fn recover_token<'a>(&'a self, token: &'a str) -> Option<Grant<'a>> {
        self.signer.tag("token").extract(token).ok()
    }

    fn recover_refresh<'a>(&'a self, token: &'a str) -> Option<Grant<'a>> {
        self.signer.tag("refresh").extract(token).ok()
    }
}
