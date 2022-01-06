use oxide_auth::frontends::dev::{NormalizedParameter, QueryParameter, WebRequest};
use axum::{
    async_trait,
    body::HttpBody,
    BoxError,
    extract::{Query, Form, FromRequest, RequestParts},
    http::header,
};
use crate::{OAuthResponse, WebError};
use std::borrow::Cow;

#[derive(Clone, Debug, Default)]
/// Type implementing `WebRequest` as well as `FromRequest` for use in route handlers
///
/// This type consumes the body of the Request upon extraction, so be careful not to use it in
/// places you also expect an application payload
pub struct OAuthRequest {
    auth: Option<String>,
    query: Option<NormalizedParameter>,
    body: Option<NormalizedParameter>,
}

/// Type implementing `WebRequest` as well as `FromRequest` for use in guarding resources
///
/// This is useful over [OAuthRequest] since [OAuthResource] doesn't consume the body of the
/// request upon extraction
pub struct OAuthResource {
    auth: Option<String>,
}

impl OAuthRequest {
    /// Fetch the authorization header from the request
    pub fn authorization_header(&self) -> Option<&str> {
        self.auth.as_deref()
    }

    /// Fetch the query for this request
    pub fn query(&self) -> Option<&NormalizedParameter> {
        self.query.as_ref()
    }

    /// Fetch the query mutably
    pub fn query_mut(&mut self) -> Option<&mut NormalizedParameter> {
        self.query.as_mut()
    }

    /// Fetch the body of the request
    pub fn body(&self) -> Option<&NormalizedParameter> {
        self.body.as_ref()
    }
}

impl From<OAuthResource> for OAuthRequest {
    fn from(r: OAuthResource) -> OAuthRequest {
        OAuthRequest {
            auth: r.auth,
            ..Default::default()
        }
    }
}

impl WebRequest for OAuthRequest {
    type Error = WebError;
    type Response = OAuthResponse;

    fn query(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
        self.query
            .as_ref()
            .map(|q| Cow::Borrowed(q as &dyn QueryParameter))
            .ok_or(WebError::Query)
    }

    fn urlbody(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
        self.body
            .as_ref()
            .map(|b| Cow::Borrowed(b as &dyn QueryParameter))
            .ok_or(WebError::Body)
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, Self::Error> {
        Ok(self.auth.as_deref().map(Cow::Borrowed))
    }
}

#[async_trait]
impl<B> FromRequest<B> for OAuthRequest
where
    B: HttpBody + Send,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Rejection = WebError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let query = Query::from_request(req)
            .await
            .ok()
            .map(|q: Query<NormalizedParameter>| q.0);

        let body = Form::from_request(req)
            .await
            .ok()
            .map(|b: Form<NormalizedParameter>| b.0);

        let mut all_auth = req.headers().unwrap().get_all(header::AUTHORIZATION).iter();
        let optional = all_auth.next();

        let auth = if all_auth.next().is_some() {
            return Err(WebError::Authorization);
        } else {
            optional.and_then(|hv| hv.to_str().ok().map(str::to_owned))
        };

        Ok(Self { auth, query, body })
    }
}

#[async_trait]
impl<B> FromRequest<B> for OAuthResource
where
    B: HttpBody + Send,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Rejection = WebError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let mut all_auth = req.headers().unwrap().get_all(header::AUTHORIZATION).iter();
        let optional = all_auth.next();

        let auth = if all_auth.next().is_some() {
            return Err(WebError::Authorization);
        } else {
            optional.and_then(|hv| hv.to_str().ok().map(str::to_owned))
        };

        Ok(Self { auth })
    }
}
