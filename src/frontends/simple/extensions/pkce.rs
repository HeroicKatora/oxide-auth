use std::borrow::Cow;

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

        ExtensionResult::Data(ExtensionData::private(Some(encoded)))
    }
}

impl AccessTokenExtension for Pkce {
    fn extend_access_token(&self, request: &AccessTokenRequest, data: Option<ExtensionData>) -> ExtensionResult {
        let encoded = match data {
            None => return ExtensionResult::Ok,
            Some(encoded) => encoded,
        };

        let verifier = match request.extension("code_verifier") {
            Some(verifier) => verifier,
            _ => return ExtensionResult::Err,
        };

        let method = match encoded.as_private() {
            Ok(Some(method)) => method,
            _ => return ExtensionResult::Err,
        };

        match self.verify(Cow::Owned(method), verifier) {
            Ok(_) => ExtensionResult::Ok,
            Err(_) => ExtensionResult::Err,
        }
    }
}
