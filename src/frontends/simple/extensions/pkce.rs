use super::{AuthorizationExtension, AuthorizationRequest, AccessTokenExtension, AccessTokenRequest};
use super::{ExtensionData, ExtensionResult};

use code_grant::extensions::Pkce;

impl AuthorizationExtension for Pkce {
    fn extend_code(&self, request: &AuthorizationRequest) -> ExtensionResult {
        let method = request.extension("code_challenge_method");
        let challenge = request.extension("code_challenge");

        let encoded = match self.challenge(method, challenge) {
            Err(()) => return ExtensionResult::Err,
            Ok(None) => return ExtensionResult::Ok,
            Ok(Some(encoded)) => encoded,
        };

        ExtensionResult::Data(encoded)
    }
}

impl AccessTokenExtension for Pkce {
    fn extend_access_token(&self, request: &AccessTokenRequest, data: Option<ExtensionData>) -> ExtensionResult {
        let verifier = request.extension("code_verifier");

        match self.verify(data, verifier) {
            Ok(_) => ExtensionResult::Ok,
            Err(_) => ExtensionResult::Err,
        }
    }
}
