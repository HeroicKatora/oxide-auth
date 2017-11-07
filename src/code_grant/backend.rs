//! Available backend algorithsm.
//!
//! The backend codifies the requirements from the rfc into types and functions as safely as
//! possible. It is, in contrast to the frontend, not concrete in the required type but rather
//! uses a very generic internal reqpresentation.
//! The result of the backend are abstract results, actions which should be executed or relayed
//! by the frontend usis its available types. Abstract in this sense means that the reponsens
//! from the backend are not generic on an input type.
//! Another consideration is the possiblilty of reusing some components with other oauth schemes.
//! In this way, the backend is used to group necessary types and as an interface to implementors,
//! to be able to infer the range of applicable end effectors (i.e. authorizers, issuer, registrars).
use super::{Authorizer, Registrar, RegistrarError};
use super::{Negotiated, NegotiationParameter};
use super::{Issuer, IssuedToken, Request};
use std::borrow::Cow;
use url::Url;
use chrono::Utc;

pub trait CodeRequest<'a> {
    fn client_id(&'a self) -> Option<Cow<'a, str>>;
    fn scope(&'a self) -> Option<Cow<'a, str>>;
    fn redirect_url(&'a self) -> Option<Cow<'a, str>>;
    fn state(&'a self) -> Option<Cow<'a, str>>;
}

/// CodeRef is a thin wrapper around necessary types to execute an authorization code grant.
pub struct CodeRef<'a> {
    registrar: &'a Registrar,
    authorizer: &'a mut Authorizer,
}

pub enum CodeError {
    Ignore /* Ignore the request entirely */,
    Redirect(Url) /* Redirect to the given url */,
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
    pub fn negotiate<'a>(&self, request: &'a CodeRequest<'a>)
    -> Result<Negotiated<'a>, CodeError> {
        // Check preconditions
        let client_id = request.client_id().ok_or(CodeError::Ignore)?;
        let redirect_url = request.redirect_url().ok_or(CodeError::Ignore)?;
        let redirect_url = Url::parse(redirect_url.as_ref()).map_err(|_| CodeError::Ignore)?;
        let redirect_url: Cow<'a, Url> = Cow::Owned(redirect_url);
        let scope = request.scope();

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
                let mut url = redirect_url.into_owned();
                url.query_pairs_mut().extend_pairs(err.into_iter());
                return Err(CodeError::Redirect(url))
            }
            Ok(negotiated) => negotiated,
        };

        Ok(Negotiated {
            client_id,
            redirect_url: redirect_url.into_owned(),
            scope
        })
    }

    /// Use negotiated parameters to authorize a client for an owner.
    pub fn authorize<'a>(&'a mut self, owner_id: Cow<'a, str>, negotiated: Negotiated<'a>, state: Option<Cow<'a, str>>)
     -> Result<Url, CodeError> {
        let grant = self.authorizer.authorize(Request{
            owner_id: &owner_id,
            client_id: &negotiated.client_id,
            redirect_url: &negotiated.redirect_url,
            scope: &negotiated.scope});
        let mut url = negotiated.redirect_url;
        url.query_pairs_mut()
            .append_pair("code", grant.as_str())
            .extend_pairs(state.map(|v| ("state", v)))
            .finish();
        Ok(url)
    }

    pub fn with<'a>(registrar: &'a Registrar, t: &'a mut Authorizer) -> CodeRef<'a> {
        CodeRef { registrar, authorizer: t }
    }
}

/// Issuer is a thin wrapper around necessary types to execute an bearer token request..
pub struct IssuerRef<'a> {
    authorizer: &'a mut Authorizer,
    issuer: &'a mut Issuer,
}

impl<'u> IssuerRef<'u> {
    /// Try to redeem an authorization code.
    pub fn use_code<'a>(&'a mut self, code: String, expected_client: Cow<'a, str>, expected_url: Cow<'a, str>)
    -> Result<IssuedToken, Cow<'static, str>> {
        let saved_params = match self.authorizer.recover_parameters(code.as_ref()) {
            None => return Err("Inactive code".into()),
            Some(v) => v,
        };

        if saved_params.client_id != expected_client || expected_url != saved_params.redirect_url.as_str() {
            return Err("Invalid code".into())
        }

        if saved_params.until.as_ref() < &Utc::now() {
            return Err("Code no longer valid".into())
        }

        let token = self.issuer.issue(Request{
            client_id: &saved_params.client_id,
            owner_id: &saved_params.owner_id,
            redirect_url: &saved_params.redirect_url,
            scope: &saved_params.scope,
        });
        Ok(token)
    }

    pub fn with<'a>(t: &'a mut Authorizer, i: &'a mut Issuer) -> IssuerRef<'a> {
        IssuerRef { authorizer: t, issuer: i }
    }
}
