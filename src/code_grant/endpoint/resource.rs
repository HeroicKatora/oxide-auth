use std::borrow::Cow;

use code_grant::guard::{
    protect,
    Error as ResourceError,
    Endpoint as ResourceEndpoint,
    Request as ResourceRequest};

use super::*;

/// Guards resources by requiring OAuth authorization.
pub struct ResourceFlow<E, R> where E: Endpoint<R>, R: WebRequest {
    endpoint: WrappedResource<E, R>,
}

struct WrappedResource<E: Endpoint<R>, R: WebRequest>(E, PhantomData<R>);

struct WrappedRequest<R: WebRequest> {
    /// Original request.
    request: PhantomData<R>,

    /// The authorization token.
    authorization: Option<String>,

    /// An error if one occurred.
    error: Option<Option<R::Error>>,
}

struct Scoped<'a, E: 'a, R: 'a> {
    request: &'a mut R,
    endpoint: &'a mut E,
}

impl<E, R> ResourceFlow<E, R> where E: Endpoint<R>, R: WebRequest {
    /// Check that the endpoint supports the necessary operations for handling requests.
    ///
    /// Binds the endpoint to a particular type of request that it supports, for many
    /// implementations this is probably single type anyways.
    ///
    /// ## Panics
    ///
    /// Indirectly `execute` may panic when this flow is instantiated with an inconsistent
    /// endpoint, for details see the documentation of `Endpoint` and `execute`. For 
    /// consistent endpoints, the panic is instead caught as an error here.
    pub fn prepare(mut endpoint: E) -> Result<Self, E::Error> {
        if endpoint.issuer_mut().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        Ok(ResourceFlow {
            endpoint: WrappedResource(endpoint, PhantomData),
        })
    }

    /// Use the checked endpoint to check for authorization for a resource.
    ///
    /// ## Panics
    ///
    /// When the issuer returned by the endpoint is suddenly `None` when previously it 
    /// was `Some(_)`.
    pub fn execute(&mut self, mut request: R) -> Result<(), Result<R::Response, E::Error>> {
        let protected = {
            let wrapped = WrappedRequest::new(&mut request);

            let mut scoped = Scoped {
                request: &mut request,
                endpoint: &mut self.endpoint.0,
            };

            protect(&mut scoped, &wrapped)
        };

        protected.map_err(|err| self.denied(&mut request, err))
    }

    fn denied(&mut self, request: &mut R, error: ResourceError) -> Result<R::Response, E::Error> {
        let kind = match &error {
            ResourceError::AccessDenied { .. } => ResponseKind::Unauthorized {
                error: None,
            },
            ResourceError::NoAuthentication { .. } => ResponseKind::Unauthorized {
                error: None,
            },
            ResourceError::InvalidRequest { .. } => ResponseKind::Invalid,
        };

        let mut response = self.endpoint.0.response(request, kind)?;
        response.unauthorized(&error.www_authenticate())
            .map_err(|err| self.endpoint.0.web_error(err))?;

        Ok(response)
    }
}

impl<R: WebRequest> WrappedRequest<R> {
    fn new(request: &mut R) -> Self {
        let token = match request.authheader() {
            // TODO: this is unecessarily wasteful, we always clone.
            Ok(Some(token)) => Some(token.into_owned()),
            Ok(None) => None,
            Err(error) => return Self::from_error(error),
        };

        WrappedRequest {
            request: PhantomData,
            authorization: token,
            error: None,
        }
    }

    fn from_error(error: R::Error) -> Self {
        WrappedRequest {
            request: PhantomData,
            authorization: None,
            error: Some(Some(error)),
        }
    }
}

impl<'a, E: Endpoint<R> + 'a, R: WebRequest + 'a> ResourceEndpoint for Scoped<'a, E, R> {
    fn scopes(&mut self) -> &[Scope] {
        self.endpoint.scopes(self.request)
    }

    fn issuer(&mut self) -> &Issuer {
        self.endpoint.issuer_mut().unwrap()
    }
}

impl<R: WebRequest> ResourceRequest for WrappedRequest<R> {
    fn valid(&self) -> bool {
        self.error.is_none()
    }

    fn token(&self) -> Option<Cow<str>> {
        self.authorization.as_ref().map(|cow| cow.as_ref()).map(Cow::Borrowed)
    }
}
