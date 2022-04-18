use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum OxidePoemError {
    #[error("There was a problem with the request")]
    Request,
    #[error("Invalid Authorization Header")]
    Authorization,
    #[error("There was a problem with the server")]
    Server,
}
