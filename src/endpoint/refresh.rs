use std::borrow::Cow;

use code_grant::refresh::{
    refresh,
    Error,
    Endpoint as RefreshEndpoint,
    Request};
use primitives::grant::Grant;

use super::*;

/// Guards resources by requiring OAuth authorization.
pub struct RefreshFlow<E, R> where E: Endpoint<R>, R: WebRequest {
    endpoint: WrappedRefresh<E, R>,
}

struct WrappedRefresh<E: Endpoint<R>, R: WebRequest>{
    inner: E, 
    r_type: PhantomData<R>,
}

struct WrappedRequest<R: WebRequest> {
    /// Original request.
    request: PhantomData<R>,

    /// The authorization token.
    authorization: Option<String>,

    /// An error if one occurred.
    error: Option<Option<R::Error>>,
}

impl<E, R> RefreshFlow<E, R> where E: Endpoint<R>, R: WebRequest {
    pub fn prepare(mut endpoint: E) -> Result<Self, E::Error> {
        if endpoint.registrar().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        if endpoint.issuer_mut().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        Ok(RefreshFlow {
            endpoint: WrappedRefresh {
                inner: endpoint,
                r_type: PhantomData,
            },
        })
    }
}

