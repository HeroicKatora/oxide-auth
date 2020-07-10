pub mod refresh {
    use oxide_auth::code_grant::refresh::{BearerToken, Error, Input, Output, Refresh, Request};
    use oxide_auth::primitives::registrar::RegistrarError;

    pub trait Endpoint {
        /// Authenticate the requesting confidential client.
        fn registrar(&self) -> &dyn crate::primitives::Registrar;

        /// Recover and test the provided refresh token then issue new tokens.
        fn issuer(&mut self) -> &mut dyn crate::primitives::Issuer;
    }

    pub async fn refresh(
        handler: &mut dyn Endpoint, request: &dyn Request,
    ) -> Result<BearerToken, Error> {
        let mut refresh = Refresh::new(request);
        let mut input = Input::None;
        loop {
            match refresh.next(input.take()) {
                Output::Err(error) => return Err(error),
                Output::Ok(token) => return Ok(token),
                Output::Refresh { token, grant } => {
                    let refreshed = handler
                        .issuer()
                        .refresh(token, grant)
                        .await
                        .map_err(|()| Error::Primitive)?;
                    input = Input::Refreshed(refreshed);
                }
                Output::RecoverRefresh { token } => {
                    let recovered = handler
                        .issuer()
                        .recover_refresh(&token)
                        .await
                        .map_err(|()| Error::Primitive)?;
                    input = Input::Recovered(recovered);
                }
                Output::Unauthenticated { client, pass } => {
                    let _: () =
                        handler
                            .registrar()
                            .check(client, pass)
                            .await
                            .map_err(|err| match err {
                                RegistrarError::PrimitiveError => Error::Primitive,
                                RegistrarError::Unspecified => Error::unauthorized("basic"),
                            })?;
                    input = Input::Authenticated;
                }
            }
        }
    }
}

pub mod resource {
    use oxide_auth::code_grant::resource::{Error, Input, Output, Resource, Request};
    use oxide_auth::primitives::grant::Grant;
    use oxide_auth::primitives::scope::Scope;

    pub trait Endpoint {
        /// The list of possible scopes required by the resource endpoint.
        fn scopes(&mut self) -> &[Scope];

        /// Recover and test the provided refresh token then issue new tokens.
        fn issuer(&mut self) -> &mut dyn crate::primitives::Issuer;
    }

    pub async fn protect(handler: &mut dyn Endpoint, req: &dyn Request) -> Result<Grant, Error> {
        enum Requested {
            None,
            Request,
            Scopes,
            Grant(String),
        }

        let mut resource = Resource::new();
        let mut requested = Requested::None;
        loop {
            let input = match requested {
                Requested::None => Input::None,
                Requested::Request => Input::Request { request: req },
                Requested::Scopes => Input::Scopes(handler.scopes()),
                Requested::Grant(token) => {
                    let grant = handler
                        .issuer()
                        .recover_token(&token)
                        .await
                        .map_err(|_| Error::PrimitiveError)?;
                    Input::Recovered(grant)
                }
            };

            requested = match resource.advance(input) {
                Output::Err(error) => return Err(error),
                Output::Ok(grant) => return Ok(grant),
                Output::GetRequest => Requested::Request,
                Output::DetermineScopes => Requested::Scopes,
                Output::Recover { token } => Requested::Grant(token.to_string()),
            };
        }
    }
}

pub mod access_token {
    use async_trait::async_trait;
    use oxide_auth::code_grant::accesstoken::{
        AccessToken, Request, BearerToken, Input, Output, Error, PrimitiveError,
    };
    use oxide_auth::primitives::{
        grant::{Extensions, Grant},
        registrar::RegistrarError,
    };

    #[async_trait(?Send)]
    pub trait Extension {
        /// Inspect the request and extension data to produce extension data.
        ///
        /// The input data comes from the extension data produced in the handling of the
        /// authorization code request.
        async fn extend(
            &mut self, request: &dyn Request, data: Extensions,
        ) -> std::result::Result<Extensions, ()>;
    }

    #[async_trait(?Send)]
    impl Extension for () {
        async fn extend(
            &mut self, _: &dyn Request, _: Extensions,
        ) -> std::result::Result<Extensions, ()> {
            Ok(Extensions::new())
        }
    }

    pub trait Endpoint {
        /// Get the client corresponding to some id.
        fn registrar(&self) -> &dyn crate::primitives::Registrar;

        /// Get the authorizer from which we can recover the authorization.
        fn authorizer(&mut self) -> &mut dyn crate::primitives::Authorizer;

        /// Return the issuer instance to create the access token.
        fn issuer(&mut self) -> &mut dyn crate::primitives::Issuer;

        /// The system of used extension, extending responses.
        ///
        /// It is possible to use `&mut ()`.
        fn extension(&mut self) -> &mut dyn Extension;
    }

    pub async fn access_token(
        handler: &mut dyn Endpoint, request: &dyn Request,
    ) -> Result<BearerToken, Error> {
        enum Requested<'a> {
            None,
            Authenticate {
                client: &'a str,
                passdata: Option<&'a [u8]>,
            },
            Recover(&'a str),
            Extend {
                grant: &'a Grant,
                extensions: &'a mut Extensions,
            },
            Issue {
                grant: &'a Grant,
            },
        }

        let mut access_token = AccessToken::new(request);
        let mut requested = Requested::None;

        loop {
            let input = match requested {
                Requested::None => Input::None,
                Requested::Authenticate { client, passdata } => {
                    handler
                        .registrar()
                        .check(client, passdata)
                        .await
                        .map_err(|err| match err {
                            RegistrarError::Unspecified => Error::unauthorized("basic"),
                            RegistrarError::PrimitiveError => Error::Primitive(PrimitiveError {
                                grant: None,
                                extensions: None,
                            }),
                        })?;
                    Input::Authenticated
                }
                Requested::Recover(code) => {
                    let opt_grant = handler.authorizer().extract(code).await.map_err(|_| {
                        Error::Primitive(PrimitiveError {
                            grant: None,
                            extensions: None,
                        })
                    })?;
                    Input::Recovered(opt_grant)
                }
                Requested::Extend {
                    grant: _,
                    mut extensions,
                } => {
                    let mut access_extensions = handler
                        .extension()
                        .extend(request, extensions.clone())
                        .await
                        .map_err(|_| Error::invalid())?;
                    extensions = &mut access_extensions;
                    Input::Done
                }
                Requested::Issue { grant } => {
                    let token = handler.issuer().issue(grant.clone()).await.map_err(|_| {
                        Error::Primitive(PrimitiveError {
                            // FIXME: endpoint should get and handle these.
                            grant: None,
                            extensions: None,
                        })
                    })?;
                    Input::Issued(token)
                }
            };

            requested = match access_token.advance(input) {
                Output::Authenticate { client, passdata } => {
                    Requested::Authenticate { client, passdata }
                }
                Output::Recover { code } => Requested::Recover(code),
                Output::Extend { grant, extensions } => Requested::Extend { grant, extensions },
                Output::Issue { grant } => Requested::Issue { grant },
                Output::Ok(token) => return Ok(token),
                Output::Err(e) => return Err(e),
            };
        }
    }
}
