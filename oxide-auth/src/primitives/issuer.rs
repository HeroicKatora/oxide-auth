//! Generates bearer tokens and refresh tokens.
//!
//! Internally similar to the authorization module, tokens generated here live longer and can be
//! renewed. There exist two fundamental implementation as well, one utilizing in memory hash maps
//! while the other uses cryptographic signing.
use std::collections::HashMap;
use std::sync::{Arc, MutexGuard, RwLockWriteGuard};
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::{Duration, Utc};

use super::Time;
use super::grant::Grant;
use super::generator::TagGrant;

/// Issuers create bearer tokens.
///
/// It's the issuers decision whether a refresh token is offered or not. In any case, it is also
/// responsible for determining the validity and parameters of any possible token string. Some
/// backends or frontends may decide not to propagate the refresh token (for example because
/// they do not intend to offer a statefull refresh api).
pub trait Issuer {
    /// Create a token authorizing the request parameters
    fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()>;

    /// Refresh a token.
    fn refresh(&mut self, _refresh: &str, _grant: Grant) -> Result<RefreshedToken, ()> {
        Err(())
    }

    /// Get the values corresponding to a bearer token
    fn recover_token<'a>(&'a self, &'a str) -> Result<Option<Grant>, ()>;

    /// Get the values corresponding to a refresh token
    fn recover_refresh<'a>(&'a self, &'a str) -> Result<Option<Grant>, ()>;
}

pub trait Tagged<'a>: TagGrant {
    /// The Signer produced by this Tagged type
    type Signer: Signer + 'a;

    /// Get a reference to generator for the given tag.
    fn tag(&'a self, tag: &'a str) -> Self::Signer;
}

pub trait Signer {
    /// Sign the grant for this usage.
    ///
    /// This commits to a token that can be used–according to the usage tag–while the endpoint can
    /// trust in it belonging to the encoded grant. `counter` must be unique for each call to this
    /// function, similar to an IV to prevent accidentally producing the same token for the same
    /// grant (which may have multiple tokens). Note that the `tag` will be recovered and checked
    /// while the IV will not.
    fn sign(&self, counter: u64, grant: &Grant) -> Result<String, ()>;

    /// Inverse operation of generate, retrieve the underlying token.
    ///
    /// Result in an Err if either the signature is invalid or if the tag does not match the
    /// expected usage tag given to this assertion.
    fn extract(&self, token: &str) -> Result<Grant, ()>;
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

/// Refresh token information returned to a client.
#[derive(Clone, Debug)]
pub struct RefreshedToken {
    /// The bearer token.
    pub token: String,

    /// The new refresh token.
    ///
    /// If this is set, the old refresh token has been invalidated.
    pub refresh: Option<String>,

    /// Expiration timestamp (Utc).
    ///
    /// Technically, a time to live is expected in the response but this will be transformed later.
    /// In a direct backend access situation, this enables high precision timestamps.
    pub until: Time,
}

/// Keeps track of access and refresh tokens by a hash-map.
///
/// The generator is itself trait based and can be chosen during construction. It is assumed to not
/// be possible (or at least very unlikely during their overlapping lifetime) for two different
/// grants to generate the same token in the grant tagger.
pub struct TokenMap<G: TagGrant=Box<dyn TagGrant + Send + Sync + 'static>> {
    duration: Option<Duration>,
    generator: G,
    usage: u64,
    access: HashMap<Arc<str>, Arc<Token>>,
    refresh: HashMap<Arc<str>, Arc<Token>>,
}

struct Token {
    /// Back link to the access token.
    access: Arc<str>,

    /// Link to a refresh token for this grant, if it exists.
    refresh: Option<Arc<str>>,

    /// The grant that was originally granted.
    grant: Grant,
}

impl<G: TagGrant> TokenMap<G> {
    /// Construct a `TokenMap` from the given generator.
    pub fn new(generator: G) -> Self {
        Self {
            duration: None,
            generator,
            usage: 0,
            access: HashMap::new(),
            refresh: HashMap::new(),
        }
    }

    /// Set the validity of all issued grants to the specified duration.
    pub fn valid_for(&mut self, duration: Duration) {
        self.duration = Some(duration);
    }

    /// All grants are valid for their default duration.
    pub fn valid_for_default(&mut self) {
        self.duration = None;
    }

    /// Unconditionally delete grant associated with the token.
    ///
    /// This is the main advantage over signing tokens. By keeping internal state of allowed
    /// grants, the resource owner or other instances can revoke a token before it expires
    /// naturally. There is no differentiation between access and refresh tokens since these should
    /// have a marginal probability of colliding.
    pub fn revoke(&mut self, token: &str) {
        self.access.remove(token);
        self.refresh.remove(token);
    }

    /// Directly associate token with grant.
    ///
    /// No checks on the validity of the grant are performed but the expiration time of the grant
    /// is modified (if a `duration` was previously set).
    pub fn import_grant(&mut self, token: String, mut grant: Grant) {
        self.set_duration(&mut grant);
        let key: Arc<str> = Arc::from(token);
        let token = Token::from_access(key.clone(), grant);
        self.access.insert(key, Arc::new(token));
    }

    fn set_duration(&self, grant: &mut Grant) {
        if let Some(duration) = &self.duration {
            grant.until = Utc::now() + *duration;
        }
    }
}

impl Token {
    fn from_access(access: Arc<str>, grant: Grant) -> Self {
        Token {
            access,
            refresh: None,
            grant,
        }
    }

    fn from_refresh(access: Arc<str>, refresh: Arc<str>, grant: Grant) -> Self {
        Token {
            access,
            refresh: Some(refresh),
            grant,
        }
    }
}

impl IssuedToken {
    /// Construct a token that can not be refreshed.
    ///
    /// Use this constructor for custom issuers that can not revoke their tokens. Since refresh
    /// tokens are both long-lived and more powerful than their access token counterparts, it is
    /// more dangerous to have an unrevokable refresh token. This is currently semantically
    /// equivalent to an empty refresh token but may change in a future iteration of the interface.
    /// While the member attributes may change, this method will not change as quickly and thus
    /// offers some additional compatibility.
    ///
    /// ```
    /// # use oxide_auth::primitives::grant::Grant;
    /// use oxide_auth::primitives::issuer::{Issuer, IssuedToken};
    ///
    /// struct MyIssuer;
    ///
    /// impl MyIssuer {
    ///     fn access_token(&mut self, grant: &Grant) -> String {
    ///         // .. your implementation
    /// #       unimplemented!()
    ///     }
    /// }
    ///
    /// impl Issuer for MyIssuer {
    ///     fn issue(&mut self, mut grant: Grant) -> Result<IssuedToken, ()> {
    ///         let token = self.access_token(&grant);
    ///         Ok(IssuedToken::without_refresh(token, grant.until))
    ///     }
    ///     // …
    /// # fn recover_token<'t>(&'t self, token: &'t str) -> Result<Option<Grant>, ()> { Err(()) }
    /// # fn recover_refresh<'t>(&'t self, token: &'t str) -> Result<Option<Grant>, ()> { Err(()) }
    /// }
    /// ```
    pub fn without_refresh(token: String, until: Time) -> Self {
        IssuedToken {
            token,
            refresh: "".into(),
            until,
        }
    }

    /// Determine if the access token can be refreshed.
    pub fn refreshable(&self) -> bool {
        !self.refresh.is_empty()
    }
}

impl<G: TagGrant> Issuer for TokenMap<G> {
    fn issue(&mut self, mut grant: Grant) -> Result<IssuedToken, ()> {
        self.set_duration(&mut grant);
        // The (usage, grant) tuple needs to be unique. Since this wraps after 2^63 operations, we
        // expect the validity time of the grant to have changed by then. This works when you don't
        // set your system time forward/backward ~10billion seconds, assuming ~10^9 operations per
        // second.
        let next_usage = self.usage.wrapping_add(2);

        let (access, refresh) = {
            let access = self.generator.tag(self.usage, &grant)?;
            let refresh = self.generator.tag(self.usage.wrapping_add(1), &grant)?;
            (access, refresh)
        };

        let until = grant.until.clone();
        let access_key: Arc<str> = Arc::from(access.clone());
        let refresh_key: Arc<str> = Arc::from(refresh.clone());
        let token = Token::from_refresh(access_key.clone(), refresh_key.clone(), grant);
        let token = Arc::new(token);

        self.access.insert(access_key, token.clone());
        self.refresh.insert(refresh_key, token);
        self.usage = next_usage;
        Ok(IssuedToken {
            token: access,
            refresh,
            until,
        })
    }

    fn refresh(&mut self, refresh: &str, mut grant: Grant) -> Result<RefreshedToken, ()> {
        // Remove the old token.
        let (refresh_key, mut token) = self.refresh.remove_entry(refresh)
            // Should only be called on valid refresh tokens.
            .ok_or(())?
            .clone();

        assert!(Arc::ptr_eq(token.refresh.as_ref().unwrap(), &refresh_key));
        self.set_duration(&mut grant);
        let until = grant.until.clone();

        let next_usage = self.usage.wrapping_add(1);
        let new_access = self.generator.tag(self.usage, &grant)?;
        let new_key: Arc<str> = Arc::from(new_access.clone());

        if let Some(atoken) = self.access.remove(&token.access) {
            assert!(Arc::ptr_eq(&token, &atoken));
        }

        {
            // Should now be the only `Arc` pointing to this.
            let mut_token = Arc::get_mut(&mut token).unwrap_or_else(
                || unreachable!("Grant data was only shared with access and refresh"));
            // Remove the old access token, insert the new.
            mut_token.access = new_key.clone();
            mut_token.grant = grant;
        }

        self.access.insert(new_key, token.clone());
        self.refresh.insert(refresh_key, token);

        self.usage = next_usage;
        Ok(RefreshedToken {
            token: new_access,
            refresh: None,
            until,
        })
    }

    fn recover_token<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        Ok(self.access.get(token).map(|token| token.grant.clone()))
    }

    fn recover_refresh<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        Ok(self.refresh.get(token).map(|token| token.grant.clone()))
    }
}

/// Signs grants instead of storing them.
///
/// Although this token instance allows preservation of memory it also implies that tokens, once
/// issued, are impossible to revoke.
pub struct TokenSigner<T> {
    duration: Option<Duration>,
    signer: T,
    // FIXME: make this an AtomicU64 once stable.
    counter: AtomicUsize,
    have_refresh: bool,
}

impl<T> TokenSigner<T>
where
    T: TagGrant,
{
    /// Construct a signing instance from a private signing key.
    ///
    /// Security notice: Never use a password alone to construct the signing key. Instead, generate
    /// a new key using a utility such as `openssl rand` that you then store away securely.
    pub fn new(secret: T) -> TokenSigner<T> {
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
    pub fn ephemeral() -> TokenSigner<T>
    where
        T: Default,
    {
        TokenSigner::new(Default::default())
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

    fn refreshable_token(&self, grant: &Grant) -> Result<IssuedToken, ()>
    where
        for <'a> T: Tagged<'a>,
    {
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

    fn unrefreshable_token(&self, grant: &Grant) -> Result<IssuedToken, ()>
    where
        for <'a> T: Tagged<'a>,
    {
        let counter = self.next_counter() as u64;

        let token = self.as_token()
            .sign(counter, grant)?;

        Ok(IssuedToken::without_refresh(token, grant.until))
    }

    fn as_token(&self) -> <T as Tagged>::Signer
    where
        for <'a> T: Tagged<'a>,
    {
        self.signer.tag("token")
    }

    fn as_refresh(&self) -> <T as Tagged>::Signer
    where
        for <'a> T: Tagged<'a>,
    {
        self.signer.tag("refresh")
    }
}

impl<'s, I: Issuer + ?Sized> Issuer for &'s mut I {
    fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        (**self).issue(grant)
    }

    fn refresh(&mut self, token: &str, grant: Grant) -> Result<RefreshedToken, ()> {
        (**self).refresh(token, grant)
    }

    fn recover_token<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        (**self).recover_token(token)
    }

    fn recover_refresh<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        (**self).recover_refresh(token)
    }
}

impl<I: Issuer + ?Sized> Issuer for Box<I> {
    fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        (**self).issue(grant)
    }

    fn refresh(&mut self, token: &str, grant: Grant) -> Result<RefreshedToken, ()> {
        (**self).refresh(token, grant)
    }

    fn recover_token<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        (**self).recover_token(token)
    }

    fn recover_refresh<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        (**self).recover_refresh(token)
    }
}

impl<'s, I: Issuer + ?Sized> Issuer for MutexGuard<'s, I> {
    fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        (**self).issue(grant)
    }

    fn refresh(&mut self, token: &str, grant: Grant) -> Result<RefreshedToken, ()> {
        (**self).refresh(token, grant)
    }

    fn recover_token<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        (**self).recover_token(token)
    }

    fn recover_refresh<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        (**self).recover_refresh(token)
    }
}

impl<'s, I: Issuer + ?Sized> Issuer for RwLockWriteGuard<'s, I> {
    fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        (**self).issue(grant)
    }

    fn refresh(&mut self, token: &str, grant: Grant) -> Result<RefreshedToken, ()> {
        (**self).refresh(token, grant)
    }

    fn recover_token<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        (**self).recover_token(token)
    }

    fn recover_refresh<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        (**self).recover_refresh(token)
    }
}

impl<T> Issuer for TokenSigner<T>
where
    for <'a> T: TagGrant + Tagged<'a>,
{
    fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        (&mut&*self).issue(grant)
    }

    fn recover_token<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        (&&*self).recover_token(token)
    }

    fn recover_refresh<'a>(&'a self, token: &'a str) -> Result<Option<Grant>, ()> {
        (&&*self).recover_refresh(token)
    }
}

impl<'a, T> Issuer for &'a TokenSigner<T>
where
    for <'b> T: TagGrant + Tagged<'b>,
{
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

    fn recover_token<'t>(&'t self, token: &'t str) -> Result<Option<Grant>, ()> {
        Ok(self.as_token().extract(token).ok())
    }

    fn recover_refresh<'t>(&'t self, token: &'t str) -> Result<Option<Grant>, ()> {
        if !self.have_refresh {
            return Ok(None)
        }

        Ok(self.as_refresh().extract(token).ok())
    }
}
