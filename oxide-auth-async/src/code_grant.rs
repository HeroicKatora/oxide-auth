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
