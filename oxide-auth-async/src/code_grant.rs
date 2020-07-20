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
                Requested::Extend { grant: _, extensions } => {
                    let access_extensions = handler
                        .extension()
                        .extend(request, extensions.clone())
                        .await
                        .map_err(|_| Error::invalid())?;

                    Input::Extended { access_extensions }
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

pub mod authorization {
    use async_trait::async_trait;
    use oxide_auth::{
        primitives::{
            prelude::ClientUrl,
            grant::{Grant, Extensions},
            registrar::{BoundClient, RegistrarError},
        },
        code_grant::{
            error::{AuthorizationError, AuthorizationErrorType},
            authorization::{Request, Authorization, Input, Error, Output, ErrorUrl},
        },
        endpoint::{PreGrant, Scope},
    };
    use url::Url;
    use chrono::{Duration, Utc};
    use std::borrow::Cow;

    /// A system of addons provided additional data.
    ///
    /// An endpoint not having any extension may use `&mut ()` as the result of system.
    #[async_trait(?Send)]
    pub trait Extension {
        /// Inspect the request to produce extension data.
        async fn extend(&mut self, request: &dyn Request) -> std::result::Result<Extensions, ()>;
    }

    #[async_trait(?Send)]
    impl Extension for () {
        async fn extend(&mut self, _: &dyn Request) -> std::result::Result<Extensions, ()> {
            Ok(Extensions::new())
        }
    }

    /// Required functionality to respond to authorization code requests.
    ///
    /// Each method will only be invoked exactly once when processing a correct and authorized request,
    /// and potentially less than once when the request is faulty.  These methods should be implemented
    /// by internally using `primitives`, as it is implemented in the `frontend` module.
    pub trait Endpoint {
        /// 'Bind' a client and redirect uri from a request to internally approved parameters.
        fn registrar(&self) -> &dyn crate::primitives::Registrar;

        /// Generate an authorization code for a given grant.
        fn authorizer(&mut self) -> &mut dyn crate::primitives::Authorizer;

        /// An extension implementation of this endpoint.
        ///
        /// It is possible to use `&mut ()`.
        fn extension(&mut self) -> &mut dyn Extension;
    }

    /// Represents a valid, currently pending authorization request not bound to an owner. The frontend
    /// can signal a reponse using this object.
    #[derive(Clone)]
    pub struct Pending {
        pre_grant: PreGrant,
        state: Option<String>,
        extensions: Extensions,
    }

    impl Pending {
        /// Denies the request, which redirects to the client for which the request originated.
        pub fn deny(self) -> Result<Url, Error> {
            let url = self.pre_grant.redirect_uri;
            let mut error = AuthorizationError::default();
            error.set_type(AuthorizationErrorType::AccessDenied);
            let error = ErrorUrl::new(url, self.state.as_deref(), error);
            Err(Error::Redirect(error))
        }

        /// Inform the backend about consent from a resource owner.
        ///
        /// Use negotiated parameters to authorize a client for an owner. The endpoint SHOULD be the
        /// same endpoint as was used to create the pending request.
        pub async fn authorize<'a>(
            self, handler: &mut dyn Endpoint, owner_id: Cow<'a, str>,
        ) -> Result<Url, Error> {
            let mut url = self.pre_grant.redirect_uri.clone();

            let grant = handler
                .authorizer()
                .authorize(Grant {
                    owner_id: owner_id.into_owned(),
                    client_id: self.pre_grant.client_id,
                    redirect_uri: self.pre_grant.redirect_uri,
                    scope: self.pre_grant.scope,
                    until: Utc::now() + Duration::minutes(10),
                    extensions: self.extensions,
                })
                .await
                .map_err(|()| Error::PrimitiveError)?;

            url.query_pairs_mut()
                .append_pair("code", grant.as_str())
                .extend_pairs(self.state.map(|v| ("state", v)))
                .finish();
            Ok(url)
        }

        /// Retrieve a reference to the negotiated parameters (e.g. scope). These should be displayed
        /// to the resource owner when asking for his authorization.
        pub fn pre_grant(&self) -> &PreGrant {
            &self.pre_grant
        }
    }

    /// Retrieve allowed scope and redirect url from the registrar.
    ///
    /// Checks the validity of any given input as the registrar instance communicates the registrated
    /// parameters. The registrar can also set or override the requested (default) scope of the client.
    /// This will result in a tuple of negotiated parameters which can be used further to authorize
    /// the client by the owner or, in case of errors, in an action to be taken.
    /// If the client is not registered, the request will otherwise be ignored, if the request has
    /// some other syntactical error, the client is contacted at its redirect url with an error
    /// response.
    pub async fn authorization_code(
        handler: &mut dyn Endpoint, request: &dyn Request,
    ) -> Result<Pending, Error> {
        enum Requested {
            None,
            Bind {
                client_id: String,
                redirect_uri: Option<Url>,
            },
            Extend,
            Negotiate {
                client_id: String,
                redirect_uri: Url,
                scope: Option<Scope>,
            },
        }

        let mut authorization = Authorization::new(request);
        let mut requested = Requested::None;
        let mut the_redirect_uri = None;

        loop {
            let input = match requested {
                Requested::None => Input::None,
                Requested::Bind {
                    client_id,
                    redirect_uri,
                } => {
                    let client_url = ClientUrl {
                        client_id: Cow::Owned(client_id),
                        redirect_uri: redirect_uri.map(|uri| Cow::Owned(uri)),
                    };
                    let bound_client = match handler.registrar().bound_redirect(client_url).await {
                        Err(RegistrarError::Unspecified) => return Err(Error::Ignore),
                        Err(RegistrarError::PrimitiveError) => return Err(Error::PrimitiveError),
                        Ok(pre_grant) => pre_grant,
                    };
                    the_redirect_uri = Some(bound_client.redirect_uri.clone().into_owned());
                    Input::Bound {
                        request,
                        bound_client,
                    }
                }
                Requested::Extend => {
                    let grant_extension = match handler.extension().extend(request).await {
                        Ok(extension_data) => extension_data,
                        Err(()) => {
                            let prepared_error = ErrorUrl::with_request(
                                request,
                                the_redirect_uri.unwrap().clone(),
                                AuthorizationErrorType::InvalidRequest,
                            );
                            return Err(Error::Redirect(prepared_error));
                        }
                    };
                    Input::Extended(grant_extension)
                }
                Requested::Negotiate {
                    client_id,
                    redirect_uri,
                    scope,
                } => {
                    let bound_client = BoundClient {
                        client_id: Cow::Owned(client_id),
                        redirect_uri: Cow::Owned(redirect_uri.clone()),
                    };
                    let pre_grant = handler.registrar().negotiate(bound_client, scope).await.map_err(
                        |err| match err {
                            RegistrarError::PrimitiveError => Error::PrimitiveError,
                            RegistrarError::Unspecified => {
                                let prepared_error = ErrorUrl::with_request(
                                    request,
                                    redirect_uri.clone(),
                                    AuthorizationErrorType::InvalidScope,
                                );
                                Error::Redirect(prepared_error)
                            }
                        },
                    )?;
                    Input::Negotiated {
                        pre_grant,
                        state: request.state().map(|s| s.into_owned()),
                    }
                }
            };

            requested = match authorization.advance(input) {
                Output::Bind {
                    client_id,
                    redirect_uri,
                } => Requested::Bind {
                    client_id,
                    redirect_uri,
                },
                Output::Extend => Requested::Extend,
                Output::Negotiate { bound_client, scope } => Requested::Negotiate {
                    client_id: bound_client.client_id.clone().into_owned(),
                    redirect_uri: bound_client.redirect_uri.clone().into_owned(),
                    scope,
                },
                Output::Ok {
                    pre_grant,
                    state,
                    extensions,
                } => {
                    return Ok(Pending {
                        pre_grant,
                        state,
                        extensions,
                    })
                }
                Output::Err(e) => return Err(e),
            };
        }
    }
}
