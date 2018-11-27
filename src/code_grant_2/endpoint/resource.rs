use std::borrow::Cow;

use code_grant_2::guard::{
    protect,
    Error as ResourceError,
    Endpoint as ResourceEndpoint,
    Request as ResourceRequest};

use super::*;

pub struct ResourceFlow<E, R> where E: Endpoint<R>, R: WebRequest {
    endpoint: WrappedResource<E, R>,
}

struct WrappedResource<E: Endpoint<R>, R: WebRequest>(E, PhantomData<R>);

struct WrappedRequest<'a, R: WebRequest + 'a> {
    /// Original request.
    request: PhantomData<R>,

    /// The authorization token.
    authorization: Option<&'a str>,

    /// An error if one occurred.
    error: Option<Option<R::Error>>,
}

impl<E, R> ResourceFlow<E, R> where E: Endpoint<R>, R: WebRequest {
    pub fn prepare(mut endpoint: E) -> Result<Self, E::Error> {
        if endpoint.issuer_mut().is_none() {
            return Err(OAuthError::PrimitiveError.into());
        }

        Ok(ResourceFlow {
            endpoint: WrappedResource(endpoint, PhantomData),
        })
    }

    pub fn execute(&mut self, mut request: R) -> Result<(), E::Error> {
        let result = protect(
            &self.endpoint,
            &WrappedRequest::new(&mut request));

        result.map_err(|err| match err {
            ResourceError::AccessDenied { .. } => unimplemented!(),
            ResourceError::NoAuthentication { .. } => unimplemented!(),
            ResourceError::InvalidRequest { .. } => unimplemented!(),
        })
    }
}

impl<'a, R: WebRequest + 'a> WrappedRequest<'a, R> {
    fn new(request: &'a R) -> Self {
        unimplemented!()
    }
}

impl<E: Endpoint<R>, R: WebRequest> ResourceEndpoint for WrappedResource<E, R> {
    fn scopes(&self) -> &[Scope] {
        unimplemented!()
    }

    fn issuer(&self) -> &Issuer {
        unimplemented!()
    }
}

impl<'a, R: WebRequest + 'a> ResourceRequest for WrappedRequest<'a, R> {
    fn valid(&self) -> bool {
        self.error.is_none()
    }

    fn token(&self) -> Option<Cow<str>> {
        self.authorization.clone().map(Cow::Borrowed)
    }
}
