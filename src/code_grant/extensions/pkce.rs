use std::borrow::Cow;

use code_grant::accesstoken::{Request as AccessTokenRequest};
use code_grant::authorization::{Request as AuthorizationRequest};
use primitives::grant::{Extension, GrantExtension};

use base64::encode as b64encode;
use ring::digest::{SHA256, digest};
use ring::constant_time::verify_slices_are_equal;

/// Proof Key for Code Exchange by OAuth Public Clients
///
/// > Auth 2.0 public clients utilizing the Authorization Code Grant are
/// susceptible to the authorization code interception attack.  This
/// specification describes the attack as well as a technique to mitigate
/// against the threat through the use of Proof Key for Code Exchange
/// (PKCE, pronounced "pixy").
///
/// (from the respective [RFC 7636])
///
/// In short, public clients share a verifier for a secret token when requesting their initial
/// authorization code. When they then make a second request to the autorization server, trading
/// this code for an access token, they can credible assure the server of their identity by
/// presenting the secret token.
///
/// The simple `plain` method only prevents attackers unable to snoop on the connection from
/// impersonating the client, while the `S256` method, which uses one-way hash functions, makes
/// any attack short of reading the victim client's memory infeasible.
///
/// Support for the `plain` method is OPTIONAL and must be turned on explicitely.
///
/// [RFC 7636]: https://tools.ietf.org/html/rfc7636
pub struct Pkce {
    required: bool,
    allow_plain: bool,
}

enum Method {
    Plain(String),
    Sha256(String),
}

impl Pkce {
    /// A pkce extensions which requires clients to use it.
    pub fn required() -> Pkce {
        Pkce {
            required: true,
            allow_plain: false,
        }
    }

    /// Pkce extension which will check verifiers if present but not require them.
    pub fn optional() -> Pkce {
        Pkce {
            required: false,
            allow_plain: false,
        }
    }

    /// Allow usage of the less secure `plain` verification method. This method is NOT secure
    /// an eavesdropping attacker such as rogue processes capturing a devices requests.
    pub fn allow_plain(&mut self) {
        self.allow_plain = true;
    }

    /// 
    pub fn challenge(&self, method: Option<Cow<str>>, challenge: Option<Cow<str>>)
        -> Result<Option<String>, ()>
    {
        let method = method.unwrap_or(Cow::Borrowed("plain"));

        let challenge = match challenge {
            None if self.required => return Err(()),
            None => return Ok(None),
            Some(challenge) => challenge,
        };

        let method = Method::from_parameter(method, challenge)?;
        let method = method.assert_supported_method(self.allow_plain)?;

        Ok(Some(method.encode()))
    }

    pub fn verify(&self, method: Cow<str>, verifier: Cow<str>)
        -> Result<(), ()>
    {
        let method = Method::from_encoded(method)?;
        method.verify(&verifier)
    }
}

impl GrantExtension for Pkce {
    fn identifier(&self) -> &'static str {
        "pkce"
    }
}

impl Method {
    fn from_parameter(method: Cow<str>, challenge: Cow<str>) -> Result<Self, ()> {
        match &*method {
            "plain" => Ok(Method::Plain(challenge.into_owned())),
            "S256" => Ok(Method::Sha256(challenge.into_owned())),
            _ => Err(()),
        }
    }

    fn assert_supported_method(self, allow_plain: bool) -> Result<Self, ()> {
        match (self, allow_plain) {
            (this, true) => Ok(this),
            (Method::Sha256(content), false) => Ok(Method::Sha256(content)),
            (Method::Plain(_), false) => Err(()),
        }
    }

    fn encode(self) -> String {
        match self {
            Method::Plain(challenge) => challenge + "p",
            Method::Sha256(challenge) => challenge + "S",
        }
    }

    fn from_encoded(encoded: Cow<str>) -> Result<Method, ()> {
        // TODO: avoid allocation in case of borrow and invalid.
        let mut encoded = encoded.into_owned();
        match encoded.pop() {
            None => Err(()),
            Some('p') => Ok(Method::Plain(encoded)),
            Some('S') => Ok(Method::Sha256(encoded)),
            _ => Err(())
        }
    }

    fn verify(&self, verifier: &str) -> Result<(), ()> {
        match self {
            &Method::Plain(ref encoded) =>
                verify_slices_are_equal(encoded.as_bytes(), verifier.as_bytes())
                    .map_err(|_| ()),
            &Method::Sha256(ref encoded) => {
                let digest = digest(&SHA256, verifier.as_bytes());
                let b64digest = b64encode(digest.as_ref());
                verify_slices_are_equal(encoded.as_bytes(), b64digest.as_bytes())
                    .map_err(|_| ())
            }
        }
    }
}
