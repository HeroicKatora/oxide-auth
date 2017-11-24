//! Available backend algorithsm.
//!
//! The backend codifies the requirements from the rfc into types and functions as safely as
//! possible. It is, in contrast to the frontend, not concrete in the required type but rather
//! uses a trait based internal reqpresentation.
//! The result of the backend are abstract results, actions which should be executed or relayed
//! by the frontend using its available types. Abstract in this sense means that the reponses
//! from the backend are not generic on an input type.
//! Another consideration is the possiblilty of reusing some components with other oauth schemes.
//! In this way, the backend is used to group necessary types and as an interface to implementors,
//! to be able to infer the range of applicable end effectors (i.e. authorizers, issuer, registrars).
use super::{Authorizer, Registrar, RegistrarError};
use super::{Negotiated, NegotiationParameter};
use super::{Issuer, IssuedToken, Request};
use super::{Scope};
use super::error::{AccessTokenError, AccessTokenErrorExt, AccessTokenErrorType};
use super::error::{AuthorizationError, AuthorizationErrorExt, AuthorizationErrorType};
use std::borrow::Cow;
use std::collections::HashMap;
use url::Url;
use chrono::Utc;
use serde_json;

/// Defines the correct treatment of the error.
/// Not all errors are signalled to the requesting party, especially when impersonation is possible
/// it is integral for security to resolve the error internally instead of redirecting the user
/// agent to a possibly crafted and malicious target.
pub enum CodeError {
    Ignore /* Ignore the request entirely */,
    Redirect(ErrorUrl) /* Redirect to the given url */,
}

/// Encapsulates a redirect to a valid redirect_url with an error response. The implementation
/// makes it possible to alter the contained error, for example to provide additional optional
/// information. The error type should not be altered by the frontend but the specificalities
/// of this should be enforced by the frontend instead.
pub struct ErrorUrl {
    base_url: Url,
    error: AuthorizationError,
}

/// Defines actions for the response to an access token request.
pub enum IssuerError {
    Invalid(ErrorDescription),
    Unauthorized(ErrorDescription, String),
}

/// Simple wrapper around AccessTokenError to imbue the type with addtional json functionality. In
/// addition this enforces backend specific behaviour for obtaining or handling the access error.
pub struct ErrorDescription {
    error: AccessTokenError,
}

/// Indicates the reason for access failure.
pub enum AccessError {
    InvalidRequest,
    AccessDenied,
}

type CodeResult<T> = Result<T, CodeError>;
type AccessTokenResult<T> = Result<T, IssuerError>;
type AccessResult<T> = Result<T, AccessError>;

///////////////////////////////////////////////////////////////////////////////////////////////////

impl ErrorUrl {
    /// Construct a new error, already fixing the state parameter if it exists.
    fn new<S>(mut url: Url, state: Option<S>, error: AuthorizationError) -> ErrorUrl where S: AsRef<str> {
        url.query_pairs_mut()
            .extend_pairs(state.as_ref().map(|st| ("state", st.as_ref())));
        ErrorUrl{ base_url: url, error: error }
    }

    /// Modify the contained error.
    pub fn with_mut<M>(&mut self, modifier: M) where M: AuthorizationErrorExt {
        modifier.modify(&mut self.error);
    }

    pub fn with<M>(mut self, modifier: M) -> Self where M: AuthorizationErrorExt {
        modifier.modify(&mut self.error);
        self
    }
}

impl Into<Url> for ErrorUrl {
    /// Finalize the error url by saving its parameters in the query part of the redirect_url
    fn into(self) -> Url {
        let mut url = self.base_url;
        url.query_pairs_mut()
            .extend_pairs(self.error.into_iter());
        url
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////

impl IssuerError {
    fn invalid<Mod>(modifier: Mod) -> IssuerError where Mod: AccessTokenErrorExt {
        IssuerError::Invalid(ErrorDescription{
            error: AccessTokenError::with((AccessTokenErrorType::InvalidRequest, modifier))
        })
    }

    fn unauthorized<Mod>(modifier: Mod, authtype: &str) -> IssuerError where Mod: AccessTokenErrorExt {
        IssuerError::Unauthorized(
            ErrorDescription{error: AccessTokenError::with((AccessTokenErrorType::InvalidClient, modifier))},
            authtype.to_string())
    }
}

impl ErrorDescription {
    pub fn to_json(self) -> String {
        use std::iter::IntoIterator;
        use std::collections::HashMap;
        let asmap = self.error.into_iter()
            .map(|(k, v)| (k.to_string(), v.into_owned()))
            .collect::<HashMap<String, String>>();
        serde_json::to_string(&asmap).unwrap()
    }
}

///////////////////////////////////////////////////////////////////////////////////////////////////

pub struct BearerToken(IssuedToken, String);

impl BearerToken {
    pub fn to_json(self) -> String {
        let remaining = self.0.until.signed_duration_since(Utc::now());
        let kvmap: HashMap<_, _> = vec![
            ("access_token", self.0.token),
            ("refresh_token", self.0.refresh),
            ("token_type", "bearer".to_string()),
            ("expires_in", remaining.num_seconds().to_string()),
            ("scope", self.1)].into_iter().collect();
        serde_json::to_string(&kvmap).unwrap()
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//                                     Authorization Endpoint                                   //
//////////////////////////////////////////////////////////////////////////////////////////////////

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
    fn redirect_url(&self) -> Option<Cow<str>>;
    /// Optional parameter the client can use to identify the redirected user-agent.
    fn state(&self) -> Option<Cow<str>>;
}

/// CodeRef is a thin wrapper around necessary types to execute an authorization code grant.
pub struct CodeRef<'a> {
    registrar: &'a Registrar,
    authorizer: &'a mut Authorizer,
}

/// Represents a valid, currently pending authorization request not bound to an owner. The frontend
/// can signal a reponse using this object.
pub struct AuthorizationRequest<'a> {
    negotiated: Negotiated<'a>,
    code: CodeRef<'a>,
    request: &'a CodeRequest,
}

impl<'u> CodeRef<'u> {
    /// Retrieve allowed scope and redirect url from the registrar.
    ///
    /// Checks the validity of any given input as the registrar instance communicates the registrated
    /// parameters. The registrar can also set or override the requested (default) scope of the client.
    /// This will result in a tuple of negotiated parameters which can be used further to authorize
    /// the client by the owner or, in case of errors, in an action to be taken.
    /// If the client is not registered, the request will otherwise be ignored, if the request has
    /// some other syntactical error, the client is contacted at its redirect url with an error
    /// response.
    pub fn negotiate<'r>(self, request: &'r CodeRequest)
    -> CodeResult<AuthorizationRequest<'r>> where 'u: 'r {
        if !request.valid() {
            return Err(CodeError::Ignore)
        }

        // Check preconditions
        let client_id = request.client_id().ok_or(CodeError::Ignore)?;
        let redirect_url = request.redirect_url().ok_or(CodeError::Ignore)?;
        let redirect_url = Url::parse(redirect_url.as_ref()).map_err(|_| CodeError::Ignore)?;
        let redirect_url: Cow<Url> = Cow::Owned(redirect_url);
        let state = request.state();

        // Setup an error with url and state, makes the code flow afterwards easier
        let error_url = redirect_url.clone().into_owned();
        let prepared_error = ErrorUrl::new(error_url.clone(), state,
            AuthorizationError::with(()));

        // Extract additional parameters
        let scope = request.scope();
        let scope = match scope.map(|scope| scope.as_ref().parse()) {
            None => None,
            Some(Err(_)) =>
                return Err(CodeError::Redirect(prepared_error.with(AuthorizationErrorType::InvalidScope))),
            Some(Ok(scope)) => Some(Cow::Owned(scope)),
        };

        // Call the underlying registrar
        let parameter = NegotiationParameter {
            client_id: client_id.clone(),
            scope: scope,
            redirect_url: redirect_url.clone(),
        };

        let scope = match self.registrar.negotiate(parameter) {
            Err(RegistrarError::Unregistered) => return Err(CodeError::Ignore),
            Err(RegistrarError::MismatchedRedirect) => return Err(CodeError::Ignore),
            Err(RegistrarError::Error(err)) => {
                let error = prepared_error.with(err);
                return Err(CodeError::Redirect(error))
            }
            Ok(negotiated) => negotiated,
        };

        let negotiated = Negotiated {
            client_id,
            redirect_url: redirect_url.into_owned(),
            scope
        };

        Ok(AuthorizationRequest {
            negotiated,
            code: CodeRef { registrar: self.registrar, authorizer: self.authorizer },
            request,
        })
    }

    /// Use negotiated parameters to authorize a client for an owner.
    fn authorize<'a>(&'a mut self, owner_id: Cow<'a, str>, negotiated: Negotiated<'a>, request: &'a CodeRequest)
     -> Result<Url, CodeError> {
        let grant = self.authorizer.authorize(Request{
            owner_id: &owner_id,
            client_id: &negotiated.client_id,
            redirect_url: &negotiated.redirect_url,
            scope: &negotiated.scope});
        let mut url = negotiated.redirect_url;
        url.query_pairs_mut()
            .append_pair("code", grant.as_str())
            .extend_pairs(request.state().map(|v| ("state", v)))
            .finish();
        Ok(url)
    }

    pub fn with(registrar: &'u Registrar, t: &'u mut Authorizer) -> Self {
        CodeRef { registrar, authorizer: t }
    }
}

impl<'a> AuthorizationRequest<'a> {
    /// Denies the request, which redirects to the client for which the request originated.
    pub fn deny(self) -> CodeResult<Url> {
        let url = self.negotiated.redirect_url;
        let error = AuthorizationError::with(AuthorizationErrorType::AccessDenied);
        let error = ErrorUrl::new(url, self.request.state(), error);
        Err(CodeError::Redirect(error))
    }

    /// Inform the backend about consent from a resource owner.
    pub fn authorize(mut self, owner_id: Cow<'a, str>) -> CodeResult<Url> {
        self.code.authorize(owner_id, self.negotiated, self.request)
    }

    /// Retrieve a reference to the negotiated parameters (e.g. scope). These should be displayed
    /// to the resource owner when asking for his authorization.
    pub fn negotiated(&self) -> &Negotiated<'a> {
        &self.negotiated
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//                                      Code Issuer Endpoint                                    //
//////////////////////////////////////////////////////////////////////////////////////////////////

/// Issuer is a thin wrapper around necessary types to execute an bearer token request..
pub struct IssuerRef<'a> {
    authorizer: &'a mut Authorizer,
    issuer: &'a mut Issuer,
}

/// Necessary
pub trait AccessTokenRequest {
    /// Received request might not be encoded correctly. This method gives implementors the chance
    /// to signal that a request was received but its encoding was generally malformed. If this is
    /// the case, then no other attribute will be queried. This method exists mainly to make
    /// frontends straightforward by not having them handle special cases for malformed requests.
    fn valid(&self) -> bool;
    /// The authorization code grant for which an access token is wanted.
    fn code(&self) -> Option<Cow<str>>;
    /// User:password of a basic authorization header.
    fn authorization(&self) -> Option<(Cow<str>, Cow<str>)>;
    /// The client_id, optional parameter for public clients.
    fn client_id(&self) -> Option<Cow<str>>;
    /// Valid request have the redirect url used to request the authorization code grant.
    fn redirect_url(&self) -> Option<Cow<str>>;
    /// Valid requests have this set to "authorization_code"
    fn grant_type(&self) -> Option<Cow<str>>;
}

impl<'u> IssuerRef<'u> {
    /// Try to redeem an authorization code.
    pub fn use_code<'r>(&mut self, request: &'r AccessTokenRequest)
    -> AccessTokenResult<BearerToken> where 'u: 'r {
        if !request.valid() {
            return Err(IssuerError::invalid(()))
        }

        match request.grant_type() {
            Some(ref cow) if cow == "authorization_code" => (),
            None => return Err(IssuerError::invalid(())),
            Some(_) => return Err(IssuerError::invalid(AccessTokenErrorType::UnsupportedGrantType)),
        };

        let code = request.code()
            .ok_or(IssuerError::invalid(()))?;
        let code = code.as_ref();

        let saved_params = match self.authorizer.extract(code) {
            None => return Err(IssuerError::invalid(())),
            Some(v) => v,
        };

        let redirect_url = request.redirect_url()
            .ok_or(IssuerError::invalid(()))?;
        let redirect_url = redirect_url.as_ref();

        let client = match request.authorization() {
            Some((_client, _pass)) => Err(())
                /*TODO validate with the registrar*/
                .map_err(|_| IssuerError::unauthorized((), "basic"))?,
            None => request.client_id()
                /*TODO check this is not a confidential client*/
                .ok_or(IssuerError::invalid(()))?,
        };

        if (saved_params.client_id.as_ref(), saved_params.redirect_url.as_str()) != (&client, redirect_url) {
            return Err(IssuerError::invalid(AccessTokenErrorType::InvalidGrant))
        }

        if *saved_params.until.as_ref() < Utc::now() {
            return Err(IssuerError::invalid((AccessTokenErrorType::InvalidGrant, "Grant expired")).into())
        }

        let token = self.issuer.issue(Request{
            client_id: &saved_params.client_id,
            owner_id: &saved_params.owner_id,
            redirect_url: &saved_params.redirect_url,
            scope: &saved_params.scope,
        });
        Ok(BearerToken{0: token, 1: saved_params.scope.as_ref().to_string()})
    }

    pub fn with(t: &'u mut Authorizer, i: &'u mut Issuer) -> Self {
        IssuerRef { authorizer: t, issuer: i }
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//                                    Access protected Endpoint                                 //
//////////////////////////////////////////////////////////////////////////////////////////////////

pub struct GuardRef<'a> {
    scopes: &'a [Scope],
    issuer: &'a mut Issuer,
}

pub trait GuardRequest {
    /// Received request might not be encoded correctly. This method gives implementors the chance
    /// to signal that a request was received but its encoding was generally malformed. If this is
    /// the case, then no other attribute will be queried. This method exists mainly to make
    /// frontends straightforward by not having them handle special cases for malformed requests.
    fn valid(&self) -> bool;
    /// The bearer token trying to access some resource.
    fn token(&self) -> Option<Cow<str>>;
}

impl<'a> GuardRef<'a> {
    pub fn protect<'r>(&self, req: &'r GuardRequest)
    -> AccessResult<()> where 'a: 'r {
        if !req.valid() {
            return Err(AccessError::InvalidRequest)
        }

        let token = req.token()
            .ok_or(AccessError::AccessDenied)?;
        let grant = self.issuer.recover_token(&token)
            .ok_or(AccessError::AccessDenied)?;

        if *grant.until.as_ref() < Utc::now() {
            return Err(AccessError::AccessDenied);
        }

        if !self.scopes.iter()
            .any(|scope| grant.scope.as_ref() <= scope) {
            return Err(AccessError::AccessDenied);
        }

        return Ok(())
    }

    /// Construct a guard from an issuer backend and a choice of scopes. A grant need only have
    /// ONE of the scopes to access the resource but each scope can require multiple subscopes.
    pub fn with<S>(issuer: &'a mut Issuer, scopes: &'a S) -> Self
    where S: AsRef<[Scope]> {
        GuardRef { scopes: scopes.as_ref(), issuer: issuer }
    }
}
