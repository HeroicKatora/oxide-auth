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
