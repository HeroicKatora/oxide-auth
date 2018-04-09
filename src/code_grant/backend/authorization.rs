use std::borrow::Cow;

use url::Url;
use chrono::{Duration, Utc};

use code_grant::error::{AuthorizationError, AuthorizationErrorExt, AuthorizationErrorType};
use code_grant::extensions::CodeExtension;
use primitives::registrar::{BoundClient, ClientUrl, RegistrarError, PreGrant};
use primitives::grant::{Extensions, Grant, GrantExtension};

/// Interface required from a request to determine the handling in the backend.
pub trait CodeRequest {
    /// Received request might not be encoded correctly. This method gives implementors the chance
    /// to signal that a request was received but its encoding was generally malformed. If this is
    /// the case, then no other attribute will be queried. This method exists mainly to make
    /// frontends straightforward by not having them handle special cases for malformed requests.
    fn valid(&self) -> bool;
    /// Identity of the client trying to gain an oauth token.
    fn client_id(&self) -> Option<Cow<str>>;
    /// Optionally specifies the requested scope
    fn scope(&self) -> Option<Cow<str>>;
    /// Valid request have (one of) the registered redirect urls for this client.
    fn redirect_uri(&self) -> Option<Cow<str>>;
    /// Optional parameter the client can use to identify the redirected user-agent.
    fn state(&self) -> Option<Cow<str>>;
    /// The method requested, valid requests MUST return `code`
    fn method(&self) -> Option<Cow<str>>;
    /// Retrieve an additional parameter used in an extension
    fn extension(&self, &str) -> Option<Cow<str>>;
}

pub trait AuthorizationEndpoint {
    fn bound_redirect<'a>(&'a self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError>;

    fn authorize(&self, Grant) -> Result<String, ()>;
}

/// Retrieve allowed scope and redirect url from the registrar.
///
/// Checks the validity of any given input as the registrar instance communicates the registrated
/// parameters. The registrar can also set or override the requested (default) scope of the client.
/// This will result in a tuple of negotiated parameters which can be used further to authorize
/// the client by the owner or, in case of errors, in an action to be taken.
/// If the client is not registered, the request will otherwise be ignored, if the request has
/// some other syntactical error, the client is contacted at its redirect url with an error
/// response.
pub fn authorization_code(
    handler: &AuthorizationEndpoint,
    request: &CodeRequest,
    extensions: &[&CodeExtension])
-> CodeResult<AuthorizationRequest> {
    if !request.valid() {
        return Err(CodeError::Ignore)
    }

    // Check preconditions
    let client_id = request.client_id().ok_or(CodeError::Ignore)?;
    let redirect_uri = match request.redirect_uri() {
        None => None,
        Some(ref uri) => {
            let parsed = Url::parse(&uri).map_err(|_| CodeError::Ignore)?;
            Some(Cow::Owned(parsed))
        },
    };

    let client_url = ClientUrl {
        client_id,
        redirect_uri,
    };

    let bound_client = match handler.bound_redirect(client_url) {
        Err(RegistrarError::Unregistered) => return Err(CodeError::Ignore),
        Err(RegistrarError::MismatchedRedirect) => return Err(CodeError::Ignore),
        Err(RegistrarError::UnauthorizedClient) => return Err(CodeError::Ignore),
        Ok(pre_grant) => pre_grant,
    };

    let state = request.state();

    // Setup an error with url and state, makes the code flow afterwards easier
    let error_uri = bound_client.redirect_uri.clone().into_owned();
    let prepared_error = ErrorUrl::new(error_uri.clone(), state.clone(),
        AuthorizationError::with(()));

    match request.method() {
        Some(ref method) if method.as_ref() == "code"
            => (),
        _ => return Err(CodeError::Redirect(prepared_error.with(
                AuthorizationErrorType::UnsupportedResponseType))),
    }

    // Extract additional parameters
    let scope = request.scope();
    let scope = match scope.map(|scope| scope.as_ref().parse()) {
        None => None,
        Some(Err(_)) =>
            return Err(CodeError::Redirect(prepared_error.with(
                AuthorizationErrorType::InvalidScope))),
        Some(Ok(scope)) => Some(scope),
    };

    let mut grant_extensions = Extensions::new();

    for extension_instance in extensions {
        match extension_instance.extend_code(request) {
            Err(_) =>
                return Err(CodeError::Redirect(prepared_error.with(
                    AuthorizationErrorType::InvalidRequest))),
            Ok(Some(extension)) =>
                grant_extensions.set(extension_instance, extension),
            Ok(None) => (),
        }
    }

    Ok(AuthorizationRequest {
        pre_grant: bound_client.negotiate(scope),
        state: state.map(|cow| cow.into_owned()),
        extensions: grant_extensions,
    })
}

/// Represents a valid, currently pending authorization request not bound to an owner. The frontend
/// can signal a reponse using this object.
pub struct AuthorizationRequest {
    pre_grant: PreGrant,
    state: Option<String>,
    extensions: Extensions,
}

impl AuthorizationRequest {
    /// Denies the request, which redirects to the client for which the request originated.
    pub fn deny(self) -> CodeResult<Url> {
        let url = self.pre_grant.redirect_uri;
        let error = AuthorizationError::with(AuthorizationErrorType::AccessDenied);
        let error = ErrorUrl::new(url, self.state, error);
        Err(CodeError::Redirect(error))
    }

    /// Inform the backend about consent from a resource owner. Use negotiated parameters to
    /// authorize a client for an owner.
    pub fn authorize(self, handler: &AuthorizationEndpoint, owner_id: Cow<str>) -> CodeResult<Url> {
       let mut url = self.pre_grant.redirect_uri.clone();

       let grant = handler.authorize(Grant {
           owner_id: owner_id.into_owned(),
           client_id: self.pre_grant.client_id,
           redirect_uri: self.pre_grant.redirect_uri,
           scope: self.pre_grant.scope,
           until: Utc::now() + Duration::minutes(10),
           extensions: self.extensions,
       }).map_err(|()| CodeError::Ignore)?;

       url.query_pairs_mut()
           .append_pair("code", grant.as_str())
           .extend_pairs(self.state.map(|v| ("state", v)))
           .finish();
       Ok(url)
    }

    /// Retrieve a reference to the negotiated parameters (e.g. scope). These should be displayed
    /// to the resource owner when asking for his authorization.
    pub fn pre_grant(&self) -> &PreGrant {
        &self.pre_grant
    }
}

/// Defines the correct treatment of the error.
/// Not all errors are signalled to the requesting party, especially when impersonation is possible
/// it is integral for security to resolve the error internally instead of redirecting the user
/// agent to a possibly crafted and malicious target.
pub enum CodeError {
    /// Ignore the request entirely
    Ignore ,

    /// Redirect to the given url
    Redirect(ErrorUrl) ,
}

/// Encapsulates a redirect to a valid redirect_uri with an error response. The implementation
/// makes it possible to alter the contained error, for example to provide additional optional
/// information. The error type should not be altered by the frontend but the specificalities
/// of this should be enforced by the frontend instead.
pub struct ErrorUrl {
    base_uri: Url,
    error: AuthorizationError,
}

type CodeResult<T> = Result<T, CodeError>;

impl ErrorUrl {
    /// Construct a new error, already fixing the state parameter if it exists.
    fn new<S>(mut url: Url, state: Option<S>, error: AuthorizationError) -> ErrorUrl where S: AsRef<str> {
        url.query_pairs_mut()
            .extend_pairs(state.as_ref().map(|st| ("state", st.as_ref())));
        ErrorUrl{ base_uri: url, error: error }
    }

    /// Modify the contained error.
    pub fn with_mut<M>(&mut self, modifier: M) where M: AuthorizationErrorExt {
        modifier.modify(&mut self.error);
    }

    /// Modify the error by moving it.
    pub fn with<M>(mut self, modifier: M) -> Self where M: AuthorizationErrorExt {
        modifier.modify(&mut self.error);
        self
    }
}

impl Into<Url> for ErrorUrl {
    /// Finalize the error url by saving its parameters in the query part of the redirect_uri
    fn into(self) -> Url {
        let mut url = self.base_uri;
        url.query_pairs_mut()
            .extend_pairs(self.error.into_iter());
        url
    }
}
