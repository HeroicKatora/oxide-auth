use oxide_auth::endpoint::{OAuthError, Template, WebRequest};

// pub use crate::code_grant::authorization::Extension as AuthorizationExtension;
pub use crate::code_grant::access_token::Extension as AccessTokenExtension;
use crate::primitives::{Authorizer, Registrar, Issuer};

pub mod access_token;

pub trait Endpoint<Request: WebRequest> {
    /// The error typed used as the error representation of each flow.
    type Error;

    /// A registrar if this endpoint can access one.
    ///
    /// Returning `None` will implicate failing any flow that requires a registrar but does not
    /// have any effect on flows that do not require one.
    fn registrar(&self) -> Option<&dyn Registrar>;

    /// An authorizer if this endpoint can access one.
    ///
    /// Returning `None` will implicate failing any flow that requires an authorizer but does not
    /// have any effect on flows that do not require one.
    fn authorizer_mut(&mut self) -> Option<&mut dyn Authorizer>;

    /// An issuer if this endpoint can access one.
    ///
    /// Returning `None` will implicate failing any flow that requires an issuer but does not have
    /// any effect on flows that do not require one.
    fn issuer_mut(&mut self) -> Option<&mut dyn Issuer>;

    /// Return the system that checks owner consent.
    ///
    /// Returning `None` will implicated failing the authorization code flow but does have any
    /// effect on other flows.
    // fn owner_solicitor(&mut self) -> Option<&mut dyn OwnerSolicitor<Request>>;

    /// Determine the required scopes for a request.
    ///
    /// The client must fulfill any one scope, so returning an empty slice will always deny the
    /// request.
    // fn scopes(&mut self) -> Option<&mut dyn Scopes<Request>>;

    /// Generate a prototype response.
    ///
    /// The endpoint can rely on this being called at most once for each flow, if it wants
    /// to preallocate the response or return a handle on an existing prototype.
    fn response(
        &mut self, request: &mut Request, kind: Template,
    ) -> Result<Request::Response, Self::Error>;

    /// Wrap an error.
    fn error(&mut self, err: OAuthError) -> Self::Error;

    /// Wrap an error in the request/response types.
    fn web_error(&mut self, err: Request::Error) -> Self::Error;

    /// Get the central extension instance this endpoint.
    ///
    /// Returning `None` is the default implementation and acts as simply providing any extensions.
    fn extension(&mut self) -> Option<&mut dyn Extension> {
        None
    }
}

pub trait Extension {
    // FIXME
    // /// The handler for authorization code extensions.
    // fn authorization(&mut self) -> Option<&mut dyn AuthorizationExtension> {
    //     None
    // }

    /// The handler for access token extensions.
    fn access_token(&mut self) -> Option<&mut dyn AccessTokenExtension> {
        None
    }
}
