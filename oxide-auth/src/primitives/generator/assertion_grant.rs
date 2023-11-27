use std::{collections::HashMap, rc::Rc, sync::Arc, borrow::Cow};

use base64::{encode, decode};
use hmac::{digest::CtOutput, Mac, Hmac};
use rand::{RngCore, thread_rng};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    primitives::{
        grant::{Grant, Extensions, Value},
        Time,
    },
    endpoint::Scope,
};

use super::TagGrant;

#[derive(Deserialize, Serialize)]
enum TokenReprInner<'a> {
    Counted(u64, SerdeAssertionGrant),
    Tagged(u64, Cow<'a, str>, SerdeAssertionGrant),
}

#[derive(Deserialize, Serialize)]
#[serde(transparent)]
/// Opaque representation of a token
pub struct TokenRepr<'a>(#[serde(borrow)] TokenReprInner<'a>);

impl<'a> From<TokenReprInner<'a>> for TokenRepr<'a> {
    fn from(value: TokenReprInner<'a>) -> Self {
        Self(value)
    }
}

/// Encoder for the components for the assertion grant
///
/// The types both implement serde's `Deserialize` and `Serialize` traits.
/// Simply turn them into a byte vector and decode them from a byte slice.
pub trait Encoder {
    /// Encode an assert grant
    fn encode_assert_grant(&self, value: AssertGrant) -> Result<Vec<u8>, ()>;

    /// Decode an assert grant
    fn decode_assert_grant(&self, value: &[u8]) -> Result<AssertGrant, ()>;

    /// Encode a token
    fn encode_token(&self, value: TokenRepr<'_>) -> Result<Vec<u8>, ()>;
    /// Decode a token
    fn decode_token<'a>(&self, value: &'a [u8]) -> Result<TokenRepr<'a>, ()>;
}

/// Generates tokens by signing its specifics with a private key.
///
/// Tokens produced by the generator include a serialized version of the grant followed by an HMAC
/// signature.  Since data is not encrypted, this token generator will ERROR if any private
/// extension is present in the grant.
///
/// The actual generator is given by a `TaggedAssertion` from `Assertion::tag` which enables
/// signing the same grant for different uses, i.e. separating authorization from bearer grants and
/// refresh tokens.
pub struct Assertion<E> {
    hasher: Hmac<sha2::Sha256>,
    encoder: E,
}

/// The cryptographic suite ensuring integrity of tokens.
#[non_exhaustive]
pub enum AssertionKind {
    /// Uses [HMAC (RFC 2104)][HMAC] with [SHA-256 (FIPS 180-4)][SHA256] hash.
    ///
    /// [HMAC]: https://tools.ietf.org/html/rfc2104
    /// [SHA256]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    HmacSha256,
}

#[derive(Serialize, Deserialize)]
struct SerdeAssertionGrant {
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

#[derive(Serialize, Deserialize)]
/// The raw grant that has contains owner details, the signature, etc.
pub struct AssertGrant(Vec<u8>, Vec<u8>);

/// Binds a tag to the data. The signature will be unique for data as well as the tag.
pub struct TaggedAssertion<'a, E>(&'a Assertion<E>, &'a str);

impl<E> Assertion<E>
where
    E: Encoder,
{
    /// Construct an assertion from a custom secret.
    ///
    /// If the key material mismatches the key length required by the selected hash algorithm then
    /// padding or shortening of the supplied key material may be applied in the form dictated by
    /// the signature type. See the respective standards.
    ///
    /// If future suites are added where this is not possible, this function may panic when supplied
    /// with an incorrect key length.
    ///
    /// Currently, the implementation lacks the ability to really make use of another hasing mechanism than
    /// hmac + sha256.
    pub fn new(kind: AssertionKind, key: &[u8], encoder: E) -> Self {
        match kind {
            AssertionKind::HmacSha256 => Assertion {
                hasher: Hmac::<sha2::Sha256>::new_from_slice(key).unwrap(),
                encoder,
            },
        }
    }

    /// Construct an assertion instance whose tokens are only valid for the program execution.
    pub fn ephemeral(encoder: E) -> Self {
        // TODO Extract KeySize from currently selected hasher
        let mut rand_bytes: [u8; 32] = [0; 32];
        thread_rng().fill_bytes(&mut rand_bytes);
        Assertion {
            hasher: Hmac::<sha2::Sha256>::new_from_slice(&rand_bytes).unwrap(),
            encoder,
        }
    }

    /// Get a reference to generator for the given tag.
    pub fn tag<'a>(&'a self, tag: &'a str) -> TaggedAssertion<'a, E> {
        TaggedAssertion(self, tag)
    }

    fn extract(&self, token: &str) -> Result<(Grant, String), ()> {
        let decoded = decode(token).map_err(|_| ())?;
        let assertion = self.encoder.decode_assert_grant(&decoded)?;

        let mut hasher = self.hasher.clone();
        hasher.update(&assertion.0);
        hasher.verify_slice(assertion.1.as_slice()).map_err(|_| ())?;

        let TokenRepr(TokenReprInner::Tagged(_, tag, serde_grant)) =
            self.encoder.decode_token(&assertion.0)?
        else {
            return Err(());
        };

        Ok((serde_grant.grant(), tag.into_owned()))
    }

    fn signature(&self, data: &[u8]) -> CtOutput<hmac::Hmac<sha2::Sha256>> {
        let mut hasher = self.hasher.clone();
        hasher.update(data);
        hasher.finalize()
    }

    fn counted_signature(&self, counter: u64, grant: &Grant) -> Result<String, ()> {
        let serde_grant = SerdeAssertionGrant::try_from(grant)?;
        let tosign = self
            .encoder
            .encode_token(TokenReprInner::Counted(counter, serde_grant).into())?;
        let signature = self.signature(&tosign);

        Ok(base64::encode(signature.into_bytes()))
    }

    fn generate_tagged(&self, counter: u64, grant: &Grant, tag: &str) -> Result<String, ()> {
        let serde_grant = SerdeAssertionGrant::try_from(grant)?;

        let tosign = self
            .encoder
            .encode_token(TokenReprInner::Tagged(counter, Cow::Borrowed(tag), serde_grant).into())?;

        let signature = self.signature(&tosign);
        let assert = AssertGrant(tosign, signature.into_bytes().to_vec());

        Ok(encode(self.encoder.encode_assert_grant(assert).unwrap()))
    }
}

impl<'a, E> TaggedAssertion<'a, E>
where
    E: Encoder,
{
    /// Sign the grant for this usage.
    ///
    /// This commits to a token that can be used–according to the usage tag–while the endpoint can
    /// trust in it belonging to the encoded grant. `counter` must be unique for each call to this
    /// function, similar to an IV to prevent accidentally producing the same token for the same
    /// grant (which may have multiple tokens). Note that the `tag` will be recovered and checked
    /// while the IV will not.
    pub fn sign(&self, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.0.generate_tagged(counter, grant, self.1)
    }

    /// Inverse operation of generate, retrieve the underlying token.
    ///
    /// Result in an Err if either the signature is invalid or if the tag does not match the
    /// expected usage tag given to this assertion.
    pub fn extract<'b>(&self, token: &'b str) -> Result<Grant, ()> {
        self.0
            .extract(token)
            .and_then(|(token, tag)| if tag == self.1 { Ok(token) } else { Err(()) })
    }
}

impl<E> TagGrant for Assertion<E>
where
    E: Encoder,
{
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.counted_signature(counter, grant)
    }
}

impl<'a, E> TagGrant for &'a Assertion<E>
where
    E: Encoder,
{
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.counted_signature(counter, grant)
    }
}

impl<E> TagGrant for Rc<Assertion<E>>
where
    E: Encoder,
{
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.counted_signature(counter, grant)
    }
}

impl<E> TagGrant for Arc<Assertion<E>>
where
    E: Encoder,
{
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.counted_signature(counter, grant)
    }
}

mod scope_serde {
    use crate::primitives::scope::Scope;

    use serde::ser::Serializer;
    use serde::de::{Deserialize, Deserializer, Error};

    pub fn serialize<S: Serializer>(scope: &Scope, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&scope.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Scope, D::Error> {
        let as_string: &str = <&str>::deserialize(deserializer)?;
        as_string.parse().map_err(Error::custom)
    }
}

mod url_serde {
    use super::Url;

    use serde::ser::Serializer;
    use serde::de::{Deserialize, Deserializer, Error};

    pub fn serialize<S: Serializer>(url: &Url, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(url.as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Url, D::Error> {
        let as_string: &str = <&str>::deserialize(deserializer)?;
        as_string.parse().map_err(Error::custom)
    }
}

mod time_serde {
    use super::Time;
    use chrono::{TimeZone, Utc};

    use serde::ser::Serializer;
    use serde::de::{Deserialize, Deserializer};

    pub fn serialize<S: Serializer>(time: &Time, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(time.timestamp())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Time, D::Error> {
        let as_timestamp: i64 = <i64>::deserialize(deserializer)?;
        Ok(Utc.timestamp_opt(as_timestamp, 0).unwrap())
    }
}

impl SerdeAssertionGrant {
    fn try_from(grant: &Grant) -> Result<Self, ()> {
        let mut public_extensions: HashMap<String, Option<String>> = HashMap::new();

        if grant.extensions.private().any(|_| true) {
            return Err(());
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

    fn grant(self) -> Grant {
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
