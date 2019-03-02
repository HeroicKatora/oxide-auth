//! Retrieve a refreshed access token.
use std::borrow::Cow;
use std::collections::HashMap;

use chrono::{Duration, Utc};

use code_grant::error::{AccessTokenError, AccessTokenErrorType};
use primitives::issuer::{RefreshedToken, Issuer};
use primitives::registrar::{Registrar, RegistrarError};

/// Required content of a refresh request.
///
/// See [Refreshing an Access Token] in the rfc.
///
/// [Refreshing an Access Token]: https://tools.ietf.org/html/rfc6749#section-6
pub trait Request {
    /// Received request might not be encoded correctly. This method gives implementors the chance
    /// to signal that a request was received but its encoding was generally malformed. If this is
    /// the case, then no other attribute will be queried. This method exists mainly to make
    /// frontends straightforward by not having them handle special cases for malformed requests.
    fn valid(&self) -> bool;

    /// The refresh token with which to refresh.
    fn refresh_token(&self) -> Option<Cow<str>>;

    /// Optionally specifies the requested scope
    fn scope(&self) -> Option<Cow<str>>;

    /// Valid requests have this set to "refresh_token"
    fn grant_type(&self) -> Option<Cow<str>>;

    /// User:password of a basic authorization header.
    fn authorization(&self) -> Option<(Cow<str>, Cow<[u8]>)>;

    /// Retrieve an additional parameter used in an extension
    fn extension(&self, key: &str) -> Option<Cow<str>>;
}

pub trait Endpoint {
    /// Authenticate the requesting confidential client.
    fn registrar(&self) -> &dyn Registrar;

    /// Recover and test the provided refresh token then issue new tokens.
    fn issuer(&mut self) -> &mut dyn Issuer;
}

/// Represents a bearer token, optional refresh token and the associated scope for serialization.
pub struct BearerToken(RefreshedToken, String);

/// Defines actions for the response to an access token request.
pub enum Error {
    /// The token did not represent a valid token.
    Invalid(ErrorDescription),

    /// The client did not properly authorize itself.
    Unauthorized(ErrorDescription, String),

    /// An underlying primitive operation did not complete successfully.
    ///
    /// This is expected to occur with some endpoints. See `PrimitiveError` for
    /// more details on when this is returned.
    Primitive,
}

/// Simple wrapper around RefreshError.
///
/// Enables addtional json functionality to generate a properly formatted response in the user of
/// this module.
pub struct ErrorDescription {
    error: AccessTokenError,
}

type Result<T> = std::result::Result<T, Error>;

/// Try to get a refreshed access token.
pub fn refresh(handler: &mut dyn Endpoint, request: &dyn Request)
    -> Result<BearerToken> 
{
    if !request.valid() {
        return Err(Error::invalid(AccessTokenErrorType::InvalidRequest))
    }

    // The server MUST authenticate the client if authentication is included.
    // ... MUST request client authentication for confidential clients.
    //
    // In effect, if this is `Some(_)` we should error due to wrong refresh token before we have
    // validated that the authorization authenticates a client? But we must inspect the token to
    // know if there is a client to validate.
    let authorization = request.authorization();
    let token = request.refresh_token();

    // MUST validate the refresh token.
    let grant = token.map(|token| {
        handler
            .issuer()
            .recover_refresh(&token)
            // Primitive error is ok, that's like internal server error.
            .map_err(|()| Error::Primitive)
    });

    let grant = match grant {
        Some(grant) => grant?,
        None => None,
    };

    let grant_client = grant.as_ref().map(|grant| grant.client_id.clone());

    // Find client to authenticate either through header or the grant data.
    //
    // Always use the header data if present to prevent 2-for-1 attempts against client auth and
    // token simultaneously.
    let (client_to_auth, passdata) = match &authorization {
        Some((client, pass)) => (Some(client.as_ref()), Some(pass.as_ref())),
        // ... MUST require client authentication for confidential clients.
        //
        // We'll see if this was confidential by trying to auth with no passdata. If that fails,
        // then the client should have authenticated with header information.
        None => (grant_client.as_ref().map(|client| client.as_str()), None),
    };

    if let Some(client) = client_to_auth {
        handler
            .registrar()
            .check(client, passdata)
            .map_err(|err| match err {
                RegistrarError::PrimitiveError => Error::Primitive,
                RegistrarError::Unspecified => Error::unauthorized("basic"),
            })?;
    }

    match request.grant_type() {
        Some(ref cow) if cow == "authorization_code" => (),
        None => return Err(Error::invalid(AccessTokenErrorType::InvalidRequest)),
        Some(_) => return Err(Error::invalid(AccessTokenErrorType::UnsupportedGrantType)),
    };

    let grant = grant
        // ... is invalid, expired, revoked, ... (Section 5.2)
        .ok_or_else(|| Error::invalid(AccessTokenErrorType::InvalidGrant))?;

    // ... MUST ensure that the refresh token was issued to the authenticated client.
    if let Some(client) = client_to_auth {
        if grant.client_id.as_str() != client {
            // ... or was issued to another client (Section 5.2)
            return Err(Error::unauthorized("basic"))
        }
    }

    let scope = match request.scope() {
        // ... is invalid, unknown, malformed (Section 5.2)
        Some(scope) => Some(scope.parse().map_err(|_| Error::invalid(AccessTokenErrorType::InvalidScope))?),
        None => None,
    };

    let scope = match scope {
        Some(scope) => {
            // ... MUST NOT include any scope not originally granted.
            if !(&scope <= &grant.scope) {
                // ... or exceeds the scope grant (Section 5.2)
                return Err(Error::invalid(AccessTokenErrorType::InvalidScope))
            }
            scope
        },
        // ... if omitted is treated as equal to the scope originally granted
        None => grant.scope.clone(),
    };

    // Update the grant with the derived data.
    let str_scope = scope.to_string();
    let mut grant = grant;
    grant.scope = scope;
    grant.until = Utc::now() + Duration::hours(1);

    let token = handler
        .issuer()
        .refresh(grant)
        .map_err(|()| Error::Primitive)?;

    Ok(BearerToken { 0: token, 1: str_scope })
}

impl Error {
    fn invalid(kind: AccessTokenErrorType) -> Self {
        Error::Invalid(ErrorDescription {
            error: AccessTokenError::new(kind),
        })
    }

    fn unauthorized(authtype: &str) -> Self {
        Error::Unauthorized(ErrorDescription {
                // ... authentication failed (Section 5.2)
                error: AccessTokenError::new(AccessTokenErrorType::InvalidClient),
            },
            authtype.to_string())
    }

    /// Get a handle to the description the client will receive.
    ///
    /// Some types of this error don't return any description which is represented by a `None`
    /// result.
    pub fn description(&mut self) -> Option<&mut AccessTokenError> {
        match self {
            Error::Invalid(description) => Some(description.description()),
            Error::Unauthorized(description, _) => Some(description.description()),
            Error::Primitive => None,
        }
    }
}

impl ErrorDescription {
    /// Get a handle to the description the client will receive.
    pub fn description(&mut self) -> &mut AccessTokenError {
        &mut self.error
    }

    pub fn to_json(&self) -> String {
        unimplemented!()
    }
}

impl BearerToken {
    /// Convert the token into a json string, viable for being sent over a network with
    /// `application/json` encoding.
    pub fn to_json(self) -> String {
        let remaining = self.0.until.signed_duration_since(Utc::now());
        let mut kvmap: HashMap<_, _> = vec![
            ("access_token", self.0.token),
            ("token_type", "bearer".to_string()),
            ("expires_in", remaining.num_seconds().to_string()),
            ("scope", self.1)].into_iter().collect();

        if let Some(refresh) = self.0.refresh {
            kvmap.insert("refresh_token", refresh);
        }

        serde_json::to_string(&kvmap).unwrap()
    }
}
