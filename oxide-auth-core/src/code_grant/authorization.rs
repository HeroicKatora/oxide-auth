//! Provides the handling for Authorization Code Requests
use std::borrow::Cow;
use std::result::Result as StdResult;

use url::Url;
use chrono::{Duration, Utc};

use code_grant::error::{AuthorizationError, AuthorizationErrorType};
use primitives::authorizer::Authorizer;
use primitives::registrar::{ClientUrl, Registrar, RegistrarError, PreGrant};
use primitives::grant::{Extensions, Grant};

/// Interface required from a request to determine the handling in the backend.
pub trait Request {
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
    fn response_type(&self) -> Option<Cow<str>>;

    /// Retrieve an additional parameter used in an extension
    fn extension(&self, key: &str) -> Option<Cow<str>>;
}

/// A system of addons provided additional data.
///
/// An endpoint not having any extension may use `&mut ()` as the result of system.
pub trait Extension {
    /// Inspect the request to produce extension data.
    fn extend(&mut self, request: &dyn Request) -> std::result::Result<Extensions, ()>;
}

impl Extension for () {
    fn extend(&mut self, _: &dyn Request) -> std::result::Result<Extensions, ()> {
        Ok(Extensions::new())
    }
}

/// Required functionality to respond to authorization code requests.
///
/// Each method will only be invoked exactly once when processing a correct and authorized request,
/// and potentially less than once when the request is faulty.  These methods should be implemented
/// by internally using `primitives`, as it is implemented in the `frontend` module.
pub trait Endpoint {
    /// 'Bind' a client and redirect uri from a request to internally approved parameters.
    fn registrar(&self) -> &dyn Registrar;

    /// Generate an authorization code for a given grant.
    fn authorizer(&mut self) -> &mut dyn Authorizer;

    /// An extension implementation of this endpoint.
    ///
    /// It is possible to use `&mut ()`.
    fn extension(&mut self) -> &mut dyn Extension;
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
pub fn authorization_code(handler: &mut dyn Endpoint, request: &dyn Request)
-> self::Result<Pending> {
    if !request.valid() {
        return Err(Error::Ignore)
    }

    // Check preconditions
    let client_id = request.client_id().ok_or(Error::Ignore)?;
    let redirect_uri = match request.redirect_uri() {
        None => None,
        Some(ref uri) => {
            let parsed = Url::parse(&uri).map_err(|_| Error::Ignore)?;
            Some(Cow::Owned(parsed))
        },
    };

    let client_url = ClientUrl {
        client_id,
        redirect_uri,
    };

    let bound_client = match handler.registrar().bound_redirect(client_url) {
        Err(RegistrarError::Unspecified) => return Err(Error::Ignore),
        Err(RegistrarError::PrimitiveError) => return Err(Error::PrimitiveError),
        Ok(pre_grant) => pre_grant,
    };

    let state = request.state();

    // Setup an error with url and state, makes the code flow afterwards easier.
    let error_uri = bound_client.redirect_uri.clone().into_owned();
    let mut prepared_error = ErrorUrl::new(error_uri.clone(), state.clone(),
        AuthorizationError::default());

    match request.response_type() {
        Some(ref method) if method.as_ref() == "code"
            => (),
        _ => {
            prepared_error.description().set_type(AuthorizationErrorType::UnsupportedResponseType);
            return Err(Error::Redirect(prepared_error))
        }
    }

    // Extract additional parameters
    let scope = request.scope();
    let scope = match scope.map(|scope| scope.as_ref().parse()) {
        None => None,
        Some(Err(_)) => {
            prepared_error.description().set_type(AuthorizationErrorType::InvalidScope);
            return Err(Error::Redirect(prepared_error))
        },
        Some(Ok(scope)) => Some(scope),
    };

    let grant_extension = match handler.extension().extend(request) {
        Ok(extension_data) => extension_data,
        Err(()) => {
            prepared_error.description().set_type(AuthorizationErrorType::InvalidRequest);
            return Err(Error::Redirect(prepared_error))
        },
    };

    let pre_grant = handler.registrar()
        .negotiate(bound_client, scope)
        .map_err(|err| match err {
            RegistrarError::PrimitiveError => Error::PrimitiveError,
            RegistrarError::Unspecified => {
                prepared_error.description().set_type(AuthorizationErrorType::InvalidScope);
                Error::Redirect(prepared_error)
            },
        })?;

    Ok(Pending {
        pre_grant,
        state: state.map(Cow::into_owned),
        extensions: grant_extension,
    })
}

/// Represents a valid, currently pending authorization request not bound to an owner. The frontend
/// can signal a reponse using this object.
pub struct Pending {
    pre_grant: PreGrant,
    state: Option<String>,
    extensions: Extensions,
}

impl Pending {
    /// Denies the request, which redirects to the client for which the request originated.
    pub fn deny(self) -> Result<Url> {
        let url = self.pre_grant.redirect_uri;
        let mut error = AuthorizationError::default();
        error.set_type(AuthorizationErrorType::AccessDenied);
        let error = ErrorUrl::new(url, self.state, error);
        Err(Error::Redirect(error))
    }

    /// Inform the backend about consent from a resource owner.
    ///
    /// Use negotiated parameters to authorize a client for an owner. The endpoint SHOULD be the
    /// same endpoint as was used to create the pending request.
    pub fn authorize(self, handler: &mut dyn Endpoint, owner_id: Cow<str>) -> Result<Url> {
       let mut url = self.pre_grant.redirect_uri.clone();

       let grant = handler.authorizer().authorize(Grant {
           owner_id: owner_id.into_owned(),
           client_id: self.pre_grant.client_id,
           redirect_uri: self.pre_grant.redirect_uri,
           scope: self.pre_grant.scope,
           until: Utc::now() + Duration::minutes(10),
           extensions: self.extensions,
       }).map_err(|()| Error::PrimitiveError)?;

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
pub enum Error {
    /// Ignore the request entirely
    Ignore,

    /// Redirect to the given url
    Redirect(ErrorUrl),

    /// Something happened in one of the primitives.
    ///
    /// The endpoint should decide how to handle this and if this is temporary.
    PrimitiveError,
}

/// Encapsulates a redirect to a valid redirect_uri with an error response. The implementation
/// makes it possible to alter the contained error, for example to provide additional optional
/// information. The error type should not be altered by the frontend but the specificalities
/// of this should be enforced by the frontend instead.
pub struct ErrorUrl {
    base_uri: Url,
    error: AuthorizationError,
}

type Result<T> = StdResult<T, Error>;

impl ErrorUrl {
    /// Construct a new error, already fixing the state parameter if it exists.
    fn new<S>(mut url: Url, state: Option<S>, error: AuthorizationError) -> ErrorUrl where S: AsRef<str> {
        url.query_pairs_mut()
            .extend_pairs(state.as_ref().map(|st| ("state", st.as_ref())));
        ErrorUrl{ base_uri: url, error }
    }

    /// Get a handle to the description the client will receive.
    pub fn description(&mut self) -> &mut AuthorizationError {
        &mut self.error
    }
}

impl Error {
    /// Get a handle to the description the client will receive.
    ///
    /// Some types of this error don't return any description which is represented by a `None`
    /// result.
    pub fn description(&mut self) -> Option<&mut AuthorizationError> {
        match self {
            Error::Ignore => None,
            Error::Redirect(inner) => Some(inner.description()),
            Error::PrimitiveError => None,
        }
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
