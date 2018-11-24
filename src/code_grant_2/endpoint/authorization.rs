use code_grant_2::authorization::{
    authorization_code,
    Error as AuthorizationError,
    ErrorUrl,
    Extension as AuthorizationExtension,
    Endpoint as AuthorizationEndpoint,
    Request as AuthorizationRequest,
    Pending};

use super::*;

/// All relevant methods for handling authorization code requests.
pub struct AuthorizationFlow<E, R> where E: Endpoint<R>, R: WebRequest {
    endpoint: WrappedAuthorization<E, R>,
    request: PhantomData<R>,
}

struct WrappedAuthorization<E: Endpoint<R>, R: WebRequest>(E, PhantomData<R>);

struct WrappedRequest<'a, R: WebRequest + 'a>{
    /// Original request.
    request: PhantomData<R>,

    /// The query in the url.
    query: Cow<'a, QueryParameter + 'static>,

    /// An error if one occurred.
    error: Option<R::Error>,
}

struct AuthorizationPending<'a, E: 'a, R: 'a> where E: Endpoint<R>, R: WebRequest {
    endpoint: &'a mut WrappedAuthorization<E, R>,
    pending: Pending,
    request: R,
}

/// A processed authentication request that is waiting for authorization by the resource owner.
pub struct AuthorizationPartial<'a, E: 'a, R: 'a> where E: Endpoint<R>, R: WebRequest {
    inner: AuthorizationPartialInner<'a, E, R>,

    /// TODO: offer this in the public api instead of dropping the request.
    _with_request: Option<Box<FnOnce(R) -> ()>>,
}

/// Result type from processing an authentication request.
enum AuthorizationPartialInner<'a, E: 'a, R: 'a> where E: Endpoint<R>, R: WebRequest {
    /// No error happened during processing and the resource owner can decide over the grant.
    Pending {
        /// A utility struct with which the request can be decided.
        pending: AuthorizationPending<'a, E, R>,
    },

    /// The request was faulty, e.g. wrong client data, but there is a well defined response.
    Failed {
        /// The request passed in.
        request: R,

        /// Final response to the client.
        ///
        /// This should be forwarded unaltered to the client. Modifications and amendments risk
        /// deviating from the OAuth2 rfc, enabling DoS, or even leaking secrets. Modify with care.
        response: R::Response,
    },

    /// An internal error happened during the request.
    Error {
        /// The request passed in.
        request: R,

        /// Error that happened while handling the request.
        error: E::Error,
    },
}

impl<E, R> AuthorizationFlow<E, R> where E: Endpoint<R>, R: WebRequest {
    /// Check that the endpoint supports the necessary operations for handling requests.
    ///
    /// Binds the endpoint to a particular type of request that it supports, for many
    /// implementations this is probably single type anyways.
    ///
    /// ## Panics
    ///
    /// Indirectly `execute` may panic when this flow is instantiated with an inconsistent
    /// endpoint, in cases that would normally have been caught as an error here.
    pub fn prepare(mut endpoint: E) -> Result<Self, E::Error> {
        if endpoint.registrar().is_none() {
            return Err(OAuthError::PrimitiveError.into());
        }

        if endpoint.authorizer_mut().is_none() {
            return Err(OAuthError::PrimitiveError.into());
        }

        Ok(AuthorizationFlow {
            endpoint: WrappedAuthorization(endpoint, PhantomData),
            request: PhantomData,
        })
    }

    /// Use the checked endpoint to execute the authorization flow for a request.
    ///
    /// ## Panics
    ///
    /// It is expected that the endpoint primitive functions are consistent, i.e. they don't begin
    /// returning `None` after having returned `Some(registrar)` previously for example. If this
    /// invariant is violated, this function may panic.
    pub fn execute(&mut self, mut request: R) -> AuthorizationPartial<E, R> {
        let negotiated = authorization_code(
            &self.endpoint,
            &WrappedRequest::new(&mut request));

        let inner = match negotiated {
            Err(err) => match authorization_error(&mut self.endpoint.0, err) {
                Ok(response) => AuthorizationPartialInner::Failed {
                    request,
                    response,
                },
                Err(error) => AuthorizationPartialInner::Error {
                    request,
                    error,
                },
            },
            Ok(negotiated) => AuthorizationPartialInner::Pending {
                pending: AuthorizationPending {
                    endpoint: &mut self.endpoint,
                    pending: negotiated,
                    request,
                }
            },
        };

        AuthorizationPartial {
            inner,
            _with_request: None,
        }
    }
}

fn authorization_error<E: Endpoint<R>, R: WebRequest>(e: &mut E, error: AuthorizationError) -> Result<R::Response, E::Error> {
    match error {
        AuthorizationError::Ignore => Err(OAuthError::DenySilently.into()),
        AuthorizationError::Redirect(target) => e.redirect_error(ErrorRedirect(target)).map_err(Into::into),
    }
}

impl<'a, E: Endpoint<R>, R: WebRequest> AuthorizationPartial<'a, E, R> {
    pub fn finish(self) -> Result<R::Response, E::Error> {
        let (_request, result) = match self.inner {
            AuthorizationPartialInner::Pending { pending, } => pending.finish(),
            AuthorizationPartialInner::Failed { request, response } => (request, Ok(response)),
            AuthorizationPartialInner::Error { request, error } => (request, Err(error)),
        };

        result
    }
}

impl<'a, E: Endpoint<R>, R: WebRequest> AuthorizationPending<'a, E, R> {
    /// Resolve the pending status using the endpoint to query owner consent.
    fn finish(mut self) -> (R, Result<R::Response, E::Error>) {
        let checked = self.endpoint
            .owner_solicitor()
            .check_consent(&mut self.request, self.pending.pre_grant());

        match checked {
            OwnerConsent::Denied => self.deny(),
            OwnerConsent::InProgress(resp) => self.in_progress(resp),
            OwnerConsent::Authorized(who) => self.authorize(who),
            OwnerConsent::Error(err) => (self.request, Err(err.into())),
        }
    }

    /// Postpones the decision over the request, to display data to the resource owner.
    ///
    /// This should happen at least once for each request unless the resource owner has already
    /// acknowledged and pre-approved a specific grant.  The response can also be used to determine
    /// the resource owner, if no login has been detected or if multiple accounts are allowed to be
    /// logged in at the same time.
    fn in_progress(self, response: R::Response) -> (R, Result<R::Response, E::Error>) {
        (self.request, Ok(response))
    }

    /// Denies the request, the client is not allowed access.
    fn deny(self) -> (R, Result<R::Response, E::Error>) {
        let result = match self.pending.deny() {
            Ok(url) => R::Response::redirect(url).map_err(Into::into),
            Err(err) => authorization_error(&mut self.endpoint.0, err),
        };

        (self.request, result)
    }

    /// Tells the system that the resource owner with the given id has approved the grant.
    fn authorize(self, who: String) -> (R, Result<R::Response, E::Error>) {
        let result = match self.pending.authorize(self.endpoint, who.into()) {
            Ok(url) => R::Response::redirect(url).map_err(Into::into),
            Err(err) => authorization_error(&mut self.endpoint.0, err),
        };

        (self.request, result)
    }
}

impl<E: Endpoint<R>, R: WebRequest> WrappedAuthorization<E, R> {
    fn owner_solicitor(&mut self) -> &mut OwnerSolicitor<R> {
        self.0.owner_solicitor().unwrap()
    }
}

impl<E: Endpoint<R>, R: WebRequest> AuthorizationEndpoint for WrappedAuthorization<E, R> {
    fn registrar(&self) -> &Registrar {
        self.0.registrar().unwrap()
    }

    fn authorizer(&mut self) -> &mut Authorizer {
        self.0.authorizer_mut().unwrap()
    }

    fn extensions(&self) -> Box<Iterator<Item=&AuthorizationExtension>> {
        // FIXME: forward extensions
        Box::new(None.into_iter())
    }
}

impl<'a, R: WebRequest + 'a> WrappedRequest<'a, R> {
    pub fn new(request: &'a mut R) -> Self {
        Self::new_or_fail(request)
            .unwrap_or_else(Self::from_err)
    }

    fn new_or_fail(request: &'a mut R) -> Result<Self, R::Error> {
        Ok(WrappedRequest {
            request: PhantomData,
            query: request.query()?,
            error: None,
        })
    }

    fn from_err(err: R::Error) -> Self {
        WrappedRequest {
            request: PhantomData,
            query: Cow::Owned(Default::default()),
            error: Some(err),
        }
    }
}

impl<'a, R: WebRequest + 'a> AuthorizationRequest for WrappedRequest<'a, R> {
    fn valid(&self) -> bool {
        self.error.is_none()
    }

    fn client_id(&self) -> Option<Cow<str>> {
        self.query.unique_value("client_id")
    }

    fn scope(&self) -> Option<Cow<str>> {
        self.query.unique_value("scope")
    }

    fn redirect_uri(&self) -> Option<Cow<str>> {
        self.query.unique_value("redirect_uri")
    }

    fn state(&self) -> Option<Cow<str>> {
        self.query.unique_value("state")
    }

    fn method(&self) -> Option<Cow<str>> {
        self.query.unique_value("method")
    }

    fn extension(&self, key: &str) -> Option<Cow<str>> {
        self.query.unique_value(key)
    }
}

