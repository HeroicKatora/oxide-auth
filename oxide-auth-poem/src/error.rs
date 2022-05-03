use poem::error::{BadRequest, InternalServerError, Unauthorized};
use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum OxidePoemError {
    #[error("There was a problem with the request")]
    Request,
    #[error("Invalid Authorization Header")]
    Authorization,
    #[error("Error while parsing header: {0}")]
    Header(String),
    #[error("There was a problem with the server")]
    Server,
}

impl From<OxidePoemError> for poem::Error {
    fn from(ox_err: OxidePoemError) -> Self {
        match &ox_err {
            OxidePoemError::Request => BadRequest(ox_err),
            OxidePoemError::Authorization => Unauthorized(ox_err),
            OxidePoemError::Header(_) | OxidePoemError::Server => InternalServerError(ox_err),
        }
    }
}
