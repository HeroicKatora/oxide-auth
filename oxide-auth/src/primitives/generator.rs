//! Generators produce string code grant and bearer tokens for a determined grant.
//!
//! In short, a code grant needs to encapsulate information about the owner, client, redirect_uri,
//! scope, and lifetime of a grant. This information needs to be uniquely recoverable.
//!
//! Two major implementation exists:
//!     - `RandomGenerator` depends on the entropy of the generated token to make guessing
//!     infeasible.
//!     - `Assertion` cryptographically verifies the integrity of a token, trading security without
//!     persistent storage for the loss of revocability. It is thus unfit for some backends, which
//!     is not currently expressed in the type system or with traits.
use super::grant::{Value, Extensions, Grant};
use super::{Url, Time};
use super::scope::Scope;

use std:: collections::HashMap;

/// Generic token for a specific grant.
///
/// The interface may be reused for authentication codes, bearer tokens and refresh tokens.
///
/// ## Requirements on implementations
///
/// When queried without repetition (users will change the `usage` counter each time), this
/// method MUST be indistinguishable from a random function. This should be the crypgraphic
/// requirements for signature schemes without requiring the verification property (the
/// function need no be deterministic). This enables two popular choices: actual signature
/// schemes and (pseudo-)random generators that ignore all input.
///
/// The requirement is derived from the fact that one should not be able to derive the tag for
/// another token from ones own. Since there may be multiple tokens for a grant, the `usage`
/// counter makes it possible for `Authorizer` and `Issuer` implementations to differentiate
/// between these.
pub trait TagGrant {
    /// For example sign the input parameters or generate a random token.
    fn tag(&mut self, usage: u64, grant: &Grant) -> Result<String, ()>;
}

#[derive(Serialize, Deserialize)]
pub struct SerdeAssertionGrant {
    /// Identifies the owner of the resource.
    owner_id: String,

    /// Identifies the client to which the grant was issued.
    client_id: String,

    /// The scope granted to the client.
    #[serde(with = "scope_serde")]
    scope: Scope,

    /// The redirection uri under which the client resides. The url package does indeed seem to
    /// parse valid URIs as well.
    #[serde(with = "url_serde")]
    redirect_uri: Url,

    /// Expiration date of the grant (Utc).
    #[serde(with = "time_serde")]
    until: Time,

    /// The public extensions, private extensions not supported currently
    public_extensions: HashMap<String, Option<String>>,
}

impl<'a, T: TagGrant + ?Sized + 'a> TagGrant for Box<T> {
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        (&mut **self).tag(counter, grant)
    }
}

impl<'a, T: TagGrant + ?Sized + 'a> TagGrant for &'a mut T {
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        (&mut **self).tag(counter, grant)
    }
}

mod scope_serde {
    use primitives::scope::Scope;

    use serde::ser::{Serializer};
    use serde::de::{Deserialize, Deserializer, Error};

    pub fn serialize<S: Serializer>(scope: &Scope, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&scope.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Scope, D::Error> {
        let as_string: &str = <(&str)>::deserialize(deserializer)?;
        as_string.parse().map_err(Error::custom)
    }
}

mod url_serde {
    use super::Url;

    use serde::ser::{Serializer};
    use serde::de::{Deserialize, Deserializer, Error};

    pub fn serialize<S: Serializer>(url: &Url, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&url.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Url, D::Error> {
        let as_string: &str = <(&str)>::deserialize(deserializer)?;
        as_string.parse().map_err(Error::custom)
    }
}

mod time_serde {
    use super::Time;
    use chrono::{TimeZone, Utc};

    use serde::ser::{Serializer};
    use serde::de::{Deserialize, Deserializer};

    pub fn serialize<S: Serializer>(time: &Time, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(time.timestamp())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Time, D::Error> {
        let as_timestamp: i64 = <i64>::deserialize(deserializer)?;
        Ok(Utc.timestamp(as_timestamp, 0))
    }
}

impl SerdeAssertionGrant {
    pub fn try_from(grant: &Grant) -> Result<Self, ()> {
        let mut public_extensions: HashMap<String, Option<String>> = HashMap::new();

        if grant.extensions.private().any(|_| true) {
            return Err(())
        }

        for (name, content) in grant.extensions.public() {
            public_extensions.insert(name.to_string(), content.map(str::to_string));
        }

        Ok(SerdeAssertionGrant {
            owner_id: grant.owner_id.clone(),
            client_id: grant.client_id.clone(),
            scope: grant.scope.clone(),
            redirect_uri: grant.redirect_uri.clone(),
            until: grant.until,
            public_extensions,
        })
    }

    pub fn grant(self) -> Grant {
        let mut extensions = Extensions::new();
        for (name, content) in self.public_extensions.into_iter() {
            extensions.set_raw(name, Value::public(content))
        }
        Grant {
            owner_id: self.owner_id,
            client_id: self.client_id,
            scope: self.scope,
            redirect_uri: self.redirect_uri,
            until: self.until,
            extensions,
        }
    }
}

#[cfg(test)]
mod tests {
    use oxide_auth_ring::generator::{Assertion, AssertionKind, RandomGenerator};

    #[test]
    #[allow(dead_code, unused)]
    fn assert_send_sync_static() {
        fn uses<T: Send + Sync + 'static>(arg: T) { }
        let _ = uses(RandomGenerator::new(16));
        let fake_key = [0u8; 16];
        let _ = uses(Assertion::new(AssertionKind::HmacSha256, &fake_key));
    }
}
