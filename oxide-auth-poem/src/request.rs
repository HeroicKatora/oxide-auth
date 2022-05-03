use std::borrow::Cow;
use poem::{
    FromRequest, Request, RequestBody,
    error::BadRequest,
    web::{Form},
};
use oxide_auth::endpoint::{NormalizedParameter, QueryParameter, WebRequest};
use crate::{error::OxidePoemError, response::OAuthResponse};

#[derive(Clone, Debug, Default)]
/// Type implementing `WebRequest` as well as `Request` for use in route handlers
///
/// This type consumes the body of the Request upon extraction, so be careful not to use it in
/// places you also expect an application payload
pub struct OAuthRequest {
    auth: Option<String>,
    query: Option<NormalizedParameter>,
    body: Option<NormalizedParameter>,
}

impl OAuthRequest {
    /// Fetch the authorization header from the request
    #[must_use]
    pub fn authorization_header(&self) -> Option<&str> {
        self.auth.as_deref()
    }

    /// Fetch the query for this request
    #[must_use]
    pub fn query(&self) -> Option<&NormalizedParameter> {
        self.query.as_ref()
    }

    /// Fetch the query mutably
    pub fn query_mut(&mut self) -> Option<&mut NormalizedParameter> {
        self.query.as_mut()
    }

    /// Fetch the body of the request
    #[must_use]
    pub fn body(&self) -> Option<&NormalizedParameter> {
        self.body.as_ref()
    }
}

impl WebRequest for OAuthRequest {
    type Error = OxidePoemError;
    type Response = OAuthResponse;

    fn query(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
        self.query
            .as_ref()
            .map(|q| Cow::Borrowed(q as &dyn QueryParameter))
            .ok_or(OxidePoemError::Request)
    }

    fn urlbody(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
        self.body
            .as_ref()
            .map(|b| Cow::Borrowed(b as &dyn QueryParameter))
            .ok_or(OxidePoemError::Request)
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, Self::Error> {
        Ok(self.auth.as_deref().map(Cow::Borrowed))
    }
}

#[poem::async_trait]
impl<'a> FromRequest<'a> for OAuthRequest {
    async fn from_request(req: &'a Request, body: &mut RequestBody) -> poem::Result<Self> {
        let query = serde_urlencoded::from_str(req.uri().query().unwrap_or("")).ok();

        let body = Form::<NormalizedParameter>::from_request(req, body)
            .await
            .ok()
            .map(|f| f.0);

        let mut all_auth = req.headers().get_all("Authorization").into_iter();
        let optional = all_auth.next();

        let auth = match all_auth.next() {
            Some(_) => return Err(BadRequest(OxidePoemError::Authorization)),
            None => optional.and_then(|header| header.to_str().ok().map(str::to_owned)),
        };

        Ok(Self { auth, query, body })
    }
}
