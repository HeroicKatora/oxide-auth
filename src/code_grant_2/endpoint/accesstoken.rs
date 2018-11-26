use std::str::from_utf8;

use code_grant_2::accesstoken::{
    access_token,
    Error as TokenError,
    Extension as TokenExtension,
    Endpoint as TokenEndpoint,
    Request as TokenRequest};

use super::*;

pub struct AccessTokenFlow<E, R> where E: Endpoint<R>, R: WebRequest {
    endpoint: WrappedToken<E, R>,
}

struct WrappedToken<E: Endpoint<R>, R: WebRequest>(E, PhantomData<R>);

struct WrappedRequest<'a, R: WebRequest + 'a> {
    /// Original request.
    request: PhantomData<R>,

    /// The query in the url.
    body: Cow<'a, QueryParameter + 'static>,

    /// The authorization tuple
    authorization: Option<Authorization>,

    /// An error if one occurred.
    error: Option<Option<R::Error>>,
}

struct Authorization(String, Vec<u8>);

impl<E, R> AccessTokenFlow<E, R> where E: Endpoint<R>, R: WebRequest {
    pub fn prepare(mut endpoint: E) -> Result<Self, E::Error> {
        unimplemented!()
    }

    pub fn execute(&mut self, mut request: R) -> () {
        unimplemented!()
    }
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

impl<'a, R: WebRequest> TokenRequest for WrappedRequest<'a, R> {
    fn valid(&self) -> bool {
        self.error.is_none()
    }

    fn code(&self) -> Option<Cow<str>> {
        self.body.unique_value("code")
    }

    fn authorization(&self) -> Option<(Cow<str>, Cow<[u8]>)> {
        self.authorization.as_ref()
            .map(|auth| (auth.0.as_str().into(), auth.1.as_slice().into()))
    }

    fn client_id(&self) -> Option<Cow<str>> {
        self.body.unique_value("client_id")
    }

    fn redirect_uri(&self) -> Option<Cow<str>> {
        self.body.unique_value("redirect_uri")
    }

    fn grant_type(&self) -> Option<Cow<str>> {
        self.body.unique_value("grant_type")
    }

    fn extension(&self, key: &str) -> Option<Cow<str>> {
        self.body.unique_value(key)
    }
}
