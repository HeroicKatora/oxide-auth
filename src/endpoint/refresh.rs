use std::borrow::Cow;
use std::marker::PhantomData;
use std::str::from_utf8;

use code_grant::refresh::{refresh, Error, Endpoint as RefreshEndpoint, Request};
use primitives::{registrar::Registrar, issuer::Issuer};
use super::{Endpoint, InnerTemplate, OAuthError, QueryParameter, WebRequest, WebResponse};

/// Guards resources by requiring OAuth authorization.
pub struct RefreshFlow<E, R> where E: Endpoint<R>, R: WebRequest {
    endpoint: WrappedRefresh<E, R>,
}

struct WrappedRefresh<E: Endpoint<R>, R: WebRequest>{
    inner: E, 
    r_type: PhantomData<R>,
}

struct WrappedRequest<'a, R: WebRequest + 'a> {
    /// Original request.
    request: PhantomData<R>,

    /// The query in the body.
    body: Cow<'a, dyn QueryParameter + 'static>,

    /// The authorization token.
    authorization: Option<Authorization>,

    /// An error if one occurred.
    error: Option<Option<R::Error>>,
}

struct Authorization(String, Vec<u8>);

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

    pub fn execute(&mut self, mut request: R) -> Result<R::Response, E::Error> {
        let refreshed = refresh(
            &mut self.endpoint,
            &WrappedRequest::new(&mut request));

        let token = match refreshed {
            Err(error) => return token_error(&mut self.endpoint.inner, &mut request, error),
            Ok(token) => token,
        };

        let mut response = self.endpoint.inner.response(&mut request, InnerTemplate::Ok.into())?;
        response.body_json(&token.to_json())
            .map_err(|err| self.endpoint.inner.web_error(err))?;
        Ok(response)
    }
}

fn token_error<E: Endpoint<R>, R: WebRequest>(endpoint: &mut E, request: &mut R, error: Error)
    -> Result<R::Response, E::Error> 
{
    Ok(match error {
        Error::Invalid(mut json) => {
            let mut response = endpoint.response(request, InnerTemplate::BadRequest {
                access_token_error: Some(json.description()),
            }.into())?;
            response.client_error()
                .map_err(|err| endpoint.web_error(err))?;
            response.body_json(&json.to_json())
                .map_err(|err| endpoint.web_error(err))?;
            response
        },
        Error::Unauthorized(mut json, scheme) =>{
            let mut response = endpoint.response(request, InnerTemplate::Unauthorized {
                error: None,
                access_token_error: Some(json.description()),
            }.into())?;
            response.unauthorized(&scheme)
                .map_err(|err| endpoint.web_error(err))?;
            response.body_json(&json.to_json())
                .map_err(|err| endpoint.web_error(err))?;
            response
        },
        Error::Primitive => {
            // FIXME: give the context for restoration.
            return Err(endpoint.error(OAuthError::PrimitiveError))
        },
    })
}

impl<'a, R: WebRequest + 'a> WrappedRequest<'a, R> {
    pub fn new(request: &'a mut R) -> Self {
        Self::new_or_fail(request)
            .unwrap_or_else(Self::from_err)
    }

    fn new_or_fail(request: &'a mut R) -> Result<Self, Option<R::Error>> {
        // If there is a header, it must parse correctly.
        let authorization = match request.authheader() {
            Err(err) => return Err(Some(err)),
            Ok(Some(header)) => Self::parse_header(header).map(Some)?,
            Ok(None) => None,
        };

        Ok(WrappedRequest {
            request: PhantomData,
            body: request.urlbody()?,
            authorization,
            error: None,
        })
    }

    fn from_err(err: Option<R::Error>) -> Self {
        WrappedRequest {
            request: PhantomData,
            body: Cow::Owned(Default::default()),
            authorization: None,
            error: Some(err),
        }
    }

    fn parse_header(header: Cow<str>) -> Result<Authorization, Option<R::Error>> {
        let authorization = {
            if !header.starts_with("Basic ") {
                return Err(None)
            }

            let combined = match base64::decode(&header[6..]) {
                Err(_) => return Err(None),
                Ok(vec) => vec,
            };

            let mut split = combined.splitn(2, |&c| c == b':');
            let client_bin = match split.next() {
                None => return Err(None),
                Some(client) => client,
            };
            let passwd = match split.next() {
                None => return Err(None),
                Some(passwd64) => passwd64,
            };

            let client = match from_utf8(client_bin) {
                Err(_) => return Err(None),
                Ok(client) => client,
            };

            Authorization(client.to_string(), passwd.to_vec())
        };

        Ok(authorization)
    }
}

impl<E: Endpoint<R>, R: WebRequest> RefreshEndpoint for WrappedRefresh<E, R> {
    fn registrar(&self) -> &dyn Registrar {
        self.inner.registrar().unwrap()
    }

    fn issuer(&mut self) -> &mut dyn Issuer {
        self.inner.issuer_mut().unwrap()
    }
}

impl<'a, R: WebRequest> Request for WrappedRequest<'a, R> {
    fn valid(&self) -> bool {
        self.error.is_none()
    }

    fn refresh_token(&self) -> Option<Cow<str>> {
        self.body.unique_value("refresh_token")
    }

    fn authorization(&self) -> Option<(Cow<str>, Cow<[u8]>)> {
        self.authorization.as_ref()
            .map(|auth| (auth.0.as_str().into(), auth.1.as_slice().into()))
    }

    fn scope(&self) -> Option<Cow<str>> {
        self.body.unique_value("scope")
    }

    fn grant_type(&self) -> Option<Cow<str>> {
        self.body.unique_value("grant_type")
    }

    fn extension(&self, key: &str) -> Option<Cow<str>> {
        self.body.unique_value(key)
    }
}
