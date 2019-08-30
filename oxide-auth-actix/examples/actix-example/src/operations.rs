use oxide_auth::{
    endpoint::{OwnerConsent, PreGrant},
    frontends::simple::endpoint::{Error, FnSolicitor},
    primitives::grant::Grant,
};
use oxide_auth_actix::{OAuthRequest, OAuthResponse, WebError};

use crate::{OxideOperation, State};

pub struct GetAuthorize(pub OAuthRequest);

impl OxideOperation for GetAuthorize {
    type Item = OAuthResponse;
    type Error = WebError;
    type Future = Result<Self::Item, Self::Error>;

    fn run(self, state: &mut State) -> Self::Future {
        state
            .endpoint()
            .with_solicitor(FnSolicitor(consent_form))
            .to_authorization()
            .execute(self.0)
            .map_err(WebError::from)
    }
}

pub struct PostAuthorize(pub OAuthRequest, pub bool);

impl OxideOperation for PostAuthorize {
    type Item = OAuthResponse;
    type Error = WebError;
    type Future = Result<Self::Item, Self::Error>;

    fn run(self, state: &mut State) -> Self::Future {
        let allowed = self.1;

        state
            .endpoint()
            .with_solicitor(FnSolicitor(move |_: &mut _, grant: &_| {
                consent_decision(allowed, grant)
            }))
            .to_authorization()
            .execute(self.0)
            .map_err(WebError::from)
    }
}

pub struct PostToken(pub OAuthRequest);

impl OxideOperation for PostToken {
    type Item = OAuthResponse;
    type Error = WebError;
    type Future = Result<Self::Item, Self::Error>;

    fn run(self, state: &mut State) -> Self::Future {
        state
            .endpoint()
            .to_access_token()
            .execute(self.0)
            .map_err(WebError::from)
    }
}

pub struct PostRefresh(pub OAuthRequest);

impl OxideOperation for PostRefresh {
    type Item = OAuthResponse;
    type Error = WebError;
    type Future = Result<Self::Item, Self::Error>;

    fn run(self, state: &mut State) -> Self::Future {
        state
            .endpoint()
            .to_refresh()
            .execute(self.0)
            .map_err(WebError::from)
    }
}

pub struct GetResource(pub OAuthRequest);

impl OxideOperation for GetResource {
    type Item = Grant;
    type Error = Result<OAuthResponse, Error<OAuthRequest>>;
    type Future = Result<Self::Item, Self::Error>;

    fn run(self, state: &mut State) -> Self::Future {
        state
            .endpoint()
            .with_scopes(vec!["default-scope".parse().unwrap()])
            .to_resource()
            .execute(self.0)
    }
}

/// A simple implementation of the first part of an authentication handler.
///
/// This will display a page to the user asking for his permission to proceed. The submitted form
/// will then trigger the other authorization handler which actually completes the flow.
fn consent_form(_: &mut OAuthRequest, grant: &PreGrant) -> OwnerConsent<OAuthResponse> {
    OwnerConsent::InProgress(OAuthResponse::ok().content_type("text/html").unwrap().body(
        &crate::support::consent_page_html("/authorize".into(), &grant),
    ))
}

/// Handle form submission by a user, completing the authorization flow.
///
/// The resource owner either accepted or denied the request.
fn consent_decision(allowed: bool, _: &PreGrant) -> OwnerConsent<OAuthResponse> {
    // No real user authentication is done here, in production you SHOULD use session keys or equivalent
    if allowed {
        OwnerConsent::Authorized("dummy user".to_string())
    } else {
        OwnerConsent::Denied
    }
}
