extern crate oxide_auth;
extern crate oxide_auth_ring;
extern crate chrono;

use oxide_auth::primitives::issuer::*;
use primitives::grant::Extensions;
use chrono::{Duration, Utc};

use oxide_auth_ring::generator::RandomGenerator;

fn grant_template() -> Grant {
    Grant {
        client_id: "Client".to_string(),
        owner_id: "Owner".to_string(),
        redirect_uri: "https://example.com".parse().unwrap(),
        scope: "default".parse().unwrap(),
        until: Utc::now() + Duration::hours(1),
        extensions: Extensions::new(),
    }
}

/// Tests the simplest invariants that should be upheld by all authorizers.
///
/// This create a token, without any extensions, an lets the issuer generate a issued token.
/// The uri is `https://example.com` and the token lasts for an hour except if overwritten.
/// Generation of a valid refresh token is not tested against.
///
/// Custom implementations may want to import and use this in their own tests.
pub fn simple_test_suite(issuer: &mut dyn Issuer) {
    let request = grant_template();

    let issued = issuer.issue(request.clone())
        .expect("Issuing failed");
    let from_token = issuer.recover_token(&issued.token)
        .expect("Issuer failed during recover")
        .expect("Issued token appears to be invalid");

    assert_ne!(issued.token, issued.refresh);
    assert_eq!(from_token.client_id, "Client");
    assert_eq!(from_token.owner_id, "Owner");
    assert!(Utc::now() < from_token.until);

    let issued_2 = issuer.issue(request)
        .expect("Issuing failed");
    assert_ne!(issued.token, issued_2.token);
    assert_ne!(issued.token, issued_2.refresh);
    assert_ne!(issued.refresh, issued_2.refresh);
    assert_ne!(issued.refresh, issued_2.token);
}

#[test]
fn signer_test_suite() {
    let mut signer = TokenSigner::ephemeral();
    // Refresh tokens must be unique if generated. If they are not even generated, they are
    // obviously not unique.
    signer.generate_refresh_tokens(true);
    simple_test_suite(&mut signer);
}

#[test]
fn signer_no_default_refresh() {
    let mut signer = TokenSigner::ephemeral();
    let issued = signer.issue(grant_template());

    let token = issued.expect("Issuing without refresh token failed");
    assert!(!token.refreshable());
}

#[test]
fn random_test_suite() {
    let mut token_map = TokenMap::new(RandomGenerator::new(16));
    simple_test_suite(&mut token_map);
}

#[test]
fn random_has_refresh() {
    let mut token_map = TokenMap::new(RandomGenerator::new(16));
    let issued = token_map.issue(grant_template());

    let token = issued.expect("Issuing without refresh token failed");
    assert!(token.refreshable());
}

#[test]
#[should_panic]
fn bad_generator() {
    struct BadGenerator;
    impl TagGrant for BadGenerator {
        fn tag(&mut self, _: u64, _: &Grant) -> Result<String, ()> {
            Ok("YOLO.HowBadCanItBeToRepeatTokens?".into())
        }
    }
    let mut token_map = TokenMap::new(BadGenerator);
    simple_test_suite(&mut token_map);
}
