//! Authorizers are need to swap code grants for bearer tokens.
//!
//! The role of an authorizer is the ensure the consistency and security of request in which a
//! client is willing to trade a code grant for a bearer token. As such, it will first issue grants
//! to client according to parameters given by the resource owner and the registrar. Upon a client
//! side request, it will then check the given parameters to determine the authorization of such
//! clients.
use std::collections::HashMap;

use super::grant::Grant;
use super::generator::TokenGenerator;

/// Authorizers create and manage authorization codes.
///
/// The authorization code can be traded for a bearer token at the token endpoint.
pub trait Authorizer {
    /// Create a code which allows retrieval of a bearer token at a later time.
    fn authorize(&mut self, Grant) -> String;

    /// Retrieve the parameters associated with a token, invalidating the code in the process. In
    /// particular, a code should not be usable twice (there is no stateless implementation of an
    /// authorizer for this reason).
    fn extract(&mut self, &str) -> Option<Grant>;
}

/// An in-memory hash map.
///
/// This authorizer saves a mapping of generated strings to their associated grants. The generator
/// is itself trait based and can be chosen during construction. It is assumed to not be possible
/// for two different grants to generate the same token in the issuer.
pub struct Storage<I: TokenGenerator> {
    issuer: I,
    tokens: HashMap<String, Grant>
}


impl<I: TokenGenerator> Storage<I> {
    /// Create a hash map authorizer with the given issuer as a backend.
    pub fn new(issuer: I) -> Storage<I> {
        Storage {issuer: issuer, tokens: HashMap::new()}
    }
}

impl<I: TokenGenerator> Authorizer for Storage<I> {
    fn authorize(&mut self, grant: Grant) -> String {
        let token = self.issuer.generate(&(&grant).into());
        self.tokens.insert(token.clone(), grant);
        token
    }

    fn extract<'a>(&mut self, grant: &'a str) -> Option<Grant> {
        self.tokens.remove(grant)
    }
}
