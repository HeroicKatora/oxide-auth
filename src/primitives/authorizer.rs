//! Authorizers are need to swap code grants for bearer tokens.
//!
//! The role of an authorizer is the ensure the consistency and security of request in which a
//! client is willing to trade a code grant for a bearer token. As such, it will first issue grants
//! to client according to parameters given by the resource owner and the registrar. Upon a client
//! side request, it will then check the given parameters to determine the authorization of such
//! clients.
use std::collections::HashMap;
use chrono::{Duration, Utc};

use super::Request;
use super::grant::{Grant, GrantRef};
use super::generator::TokenGenerator;

/// Authorizers create and manage authorization codes.
///
/// The authorization code can be traded for a bearer token at the token endpoint.
pub trait Authorizer {
    /// Create a code which allows retrieval of a bearer token at a later time.
    fn authorize(&mut self, Request) -> String;
    /// Retrieve the parameters associated with a token, invalidating the code in the process. In
    /// particular, a code should not be usable twice (there is no stateless implementation of an
    /// authorizer for this reason).
    fn extract<'a>(&mut self, &'a str) -> Option<GrantRef<'a>>;
}

pub struct Storage<I: TokenGenerator> {
    issuer: I,
    tokens: HashMap<String, Grant>
}

impl<I: TokenGenerator> Storage<I> {
    pub fn new(issuer: I) -> Storage<I> {
        Storage {issuer: issuer, tokens: HashMap::new()}
    }
}

impl<I: TokenGenerator> Authorizer for Storage<I> {
    fn authorize(&mut self, req: Request) -> String {
        let owner_id = req.owner_id.to_string();
        let client_id = req.client_id.to_string();
        let scope = req.scope.clone();
        let redirect_url = req.redirect_url.clone();
        let until = Utc::now() + Duration::minutes(10);
        let grant = Grant {owner_id, client_id, scope, redirect_url, until };

        let token = self.issuer.generate(&(&grant).into());
        self.tokens.insert(token.clone(), grant);
        token
    }

    fn extract<'a>(&mut self, grant: &'a str) -> Option<GrantRef<'a>> {
        self.tokens.remove(grant).map(|v| v.into())
    }
}
