use std::borrow::Cow;

use super::{AccessTokenExtension, CodeExtension};
use code_grant::backend::{AccessTokenRequest, CodeRequest};
use primitives::grant::{Extension, GrantExtension};

use base64::encode as b64encode;
use ring::digest::{SHA256, digest};
use ring::constant_time::verify_slices_are_equal;

pub struct Pkce {
    required: bool,
}

enum Method {
    Plain(String),
    Sha256(String),
}

impl GrantExtension for Pkce {
    fn identifier(&self) -> &'static str {
        "pkce"
    }
}

impl CodeExtension for Pkce {
    fn extend(&self, request: &CodeRequest) -> Result<Option<Extension>, ()> {
        let challenge = request.extension("code_challenge");
        let method = request.extension("code_challenge_method");

        let (challenge, method) = match (challenge, method) {
            (None, None) => if self.required {
                    return Err(())
                } else {
                    return Ok(None)
                },
            (Some(challenge), Some(method)) => (challenge, method),
            _ => return Err(()),
        };

        let method = Method::from_parameter(method, challenge)?;
        Ok(Some(Extension::private(Some(method.encode()))))
    }
}

impl AccessTokenExtension for Pkce {
    fn extend(&self, request: &AccessTokenRequest, code_extension: Option<Extension>)
        -> Result<Option<Extension>, ()> {
        let encoded = match code_extension {
            None => return Ok(None),
            Some(encoded) => encoded,
        };

        let verifier = request.extension("code_verifier").ok_or(())?;

        let private_encoded = encoded.as_private()?.ok_or(())?;
        let method = Method::from_encoded(private_encoded)?;

        method.verify(&verifier).map(|_| None)
    }
}

impl Method {
    fn from_parameter(method: Cow<str>, challenge: Cow<str>) -> Result<Self, ()> {
        match &*method {
            "Plain" => Ok(Method::Plain(challenge.into_owned())),
            "S256" => Ok(Method::Sha256(challenge.into_owned())),
            _ => Err(()),
        }
    }

    fn encode(self) -> String {
        match self {
            Method::Plain(challenge) => challenge + "P",
            Method::Sha256(challenge) => challenge + "S",
        }
    }

    fn from_encoded(mut encoded: String) -> Result<Method, ()> {
        match encoded.pop() {
            None => Err(()),
            Some('P') => Ok(Method::Plain(encoded)),
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
