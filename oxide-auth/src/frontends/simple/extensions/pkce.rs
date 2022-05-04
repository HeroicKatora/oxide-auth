use super::{AuthorizationAddon, AuthorizationRequest, AccessTokenAddon, AccessTokenRequest};
use super::{AddonResult, Value};

pub use crate::code_grant::extensions::Pkce;

impl AuthorizationAddon for Pkce {
    fn execute(&self, request: &dyn AuthorizationRequest) -> AddonResult {
        let method = request.extension("code_challenge_method");
        let challenge = request.extension("code_challenge");

        let encoded = match self.challenge(method, challenge) {
            Ok(None) => return AddonResult::Ok,
            Ok(Some(encoded)) => encoded,
            Err(_) => return AddonResult::Err,
        };

        AddonResult::Data(encoded)
    }
}

impl AccessTokenAddon for Pkce {
    fn execute(&self, request: &dyn AccessTokenRequest, data: Option<Value>) -> AddonResult {
        let verifier = request.extension("code_verifier");

        match self.verify(data, verifier) {
            Ok(_) => AddonResult::Ok,
            Err(_) => AddonResult::Err,
        }
    }
}
