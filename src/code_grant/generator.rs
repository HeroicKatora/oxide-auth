use super::{Grant, TokenGenerator};
use chrono::{Utc, TimeZone};
use std::borrow::Cow;
use rand::{thread_rng, Rng};
use ring;
use rmp_serde;
use url::Url;
use base64::{encode, decode};

pub struct RandomGenerator {
    len: usize
}

impl RandomGenerator {
    pub fn new(length: usize) -> RandomGenerator {
        RandomGenerator {len: length}
    }
}

impl TokenGenerator for RandomGenerator {
    fn generate(&self, _grant: Grant) -> String {
        let result = thread_rng().gen_iter::<u8>().take(self.len).collect::<Vec<u8>>();
        encode(&result)
    }
}

pub struct Assertion {
    secret: ring::hmac::SigningKey,
}

#[derive(Serialize, Deserialize)]
pub struct InternalAssertionGrant<'a>(&'a str, &'a str, &'a str, &'a str, (i64, u32));
#[derive(Serialize, Deserialize)]
pub struct AssertGrant<'a>(&'a [u8], &'a [u8]);

impl Assertion {
    pub fn new(key: ring::hmac::SigningKey) -> Assertion {
        Assertion { secret: key}
    }

    pub fn extract<'a>(&self, token: &'a str) -> Result<Grant<'a>, ()> {
        let readbytes = decode(token).map_err(|_| ())?;
        let AssertGrant(message, digest) = rmp_serde::from_slice(&readbytes).map_err(|_| ())?;

        ring::hmac::verify_with_own_key(&self.secret, message, digest).map_err(|_| ())?;
        let InternalAssertionGrant(owner_id, client_id, redirectbytes, scope, (ts, tsnanos)) =
            rmp_serde::from_slice(message).map_err(|_| ())?;

        let redirect_url = Url::parse(redirectbytes).map_err(|_| ())?;
        let until = Utc::timestamp(&Utc, ts, tsnanos);
        Ok(Grant{
            owner_id: Cow::Owned(owner_id.to_string()),
            client_id: Cow::Owned(client_id.to_string()),
            redirect_url: Cow::Owned(redirect_url),
            scope: Cow::Owned(scope.to_string()),
            until: Cow::Owned(until),
        })
    }
}

impl TokenGenerator for Assertion {
    fn generate(&self, grant: Grant) -> String {
        let tosign = rmp_serde::to_vec(&InternalAssertionGrant(
            &grant.owner_id,
            &grant.client_id,
            grant.redirect_url.as_str(),
            &grant.scope,
            (grant.until.timestamp(), grant.until.timestamp_subsec_nanos()))).unwrap();
        let signature = ring::hmac::sign(&self.secret, &tosign);
        encode(&rmp_serde::to_vec(&AssertGrant(&tosign, signature.as_ref())).unwrap())
    }
}
