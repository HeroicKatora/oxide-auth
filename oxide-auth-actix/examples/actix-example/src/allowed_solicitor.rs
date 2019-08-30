use oxide_auth::endpoint::{OwnerConsent, OwnerSolicitor, PreGrant, QueryParameter};
use oxide_auth_actix::{OAuthRequest, OAuthResponse};

pub struct AllowedSolicitor;

impl OwnerSolicitor<OAuthRequest> for AllowedSolicitor {
    fn check_consent(
        &mut self,
        req: &mut OAuthRequest,
        grant: &PreGrant,
    ) -> OwnerConsent<OAuthResponse> {
        // No real user authentication is done here, in production you SHOULD use session keys or equivalent
        if let Some(query) = req.query() {
            if let Some(v) = query.unique_value("allow") {
                if v == "true" {
                    OwnerConsent::Authorized("dummy user".to_string())
                } else {
                    OwnerConsent::Denied
                }
            } else if query.unique_value("deny").is_some() {
                OwnerConsent::Denied
            } else {
                progress(grant)
            }
        } else {
            progress(grant)
        }
    }
}

// This will display a page to the user asking for his permission to proceed. The submitted form
// will then trigger the other authorization handler which actually completes the flow.
fn progress(grant: &PreGrant) -> OwnerConsent<OAuthResponse> {
    OwnerConsent::InProgress(OAuthResponse::ok().content_type("text/html").unwrap().body(
        &crate::support::consent_page_html("/authorize".into(), &grant),
    ))
}
