use std::borrow::Cow;
use std::collections::HashMap;

use chrono::{Duration, Utc};
use serde_json;

use code_grant::error::{AccessTokenError, AccessTokenErrorType, AccessTokenErrorExt};
use code_grant::extensions::AccessTokenExtension;
use primitives::issuer::IssuedToken;
use primitives::grant::{Extensions, Grant};
use primitives::registrar::{RegisteredClient, RegistrarError};

/// Trait based retrieval of parameters necessary for access token request handling.
pub trait AccessTokenRequest {
    /// Received request might not be encoded correctly. This method gives implementors the chance
    /// to signal that a request was received but its encoding was generally malformed. If this is
    /// the case, then no other attribute will be queried. This method exists mainly to make
    /// frontends straightforward by not having them handle special cases for malformed requests.
    fn valid(&self) -> bool;
    /// The authorization code grant for which an access token is wanted.
    fn code(&self) -> Option<Cow<str>>;
    /// User:password of a basic authorization header.
    fn authorization(&self) -> Option<(Cow<str>, Cow<[u8]>)>;
    /// The client_id, optional parameter for public clients.
    fn client_id(&self) -> Option<Cow<str>>;
    /// Valid request have the redirect url used to request the authorization code grant.
    fn redirect_uri(&self) -> Option<Cow<str>>;
    /// Valid requests have this set to "authorization_code"
    fn grant_type(&self) -> Option<Cow<str>>;
    /// Retrieve an additional parameter used in an extension
    fn extension(&self, &str) -> Option<Cow<str>>;
}

pub trait AccessTokenEndpoint {
    fn client(&self, client_id: &str) -> Option<RegisteredClient>;

    fn extract(&self, &str) -> Option<Grant>;

    fn issue(&self, Grant) -> Result<IssuedToken, ()>;
}

/// Try to redeem an authorization code.
pub fn access_token(
    handler: &AccessTokenEndpoint,
    request: &AccessTokenRequest,
    extensions: &[&AccessTokenExtension])
-> AccessTokenResult<BearerToken> {
    if !request.valid() {
        return Err(IssuerError::invalid(()))
    }

    let authorization = request.authorization();
    let client_id = request.client_id();
    let (client_id, auth): (&str, Option<&[u8]>) = match (&client_id, &authorization) {
        (&None, &Some((ref client_id, ref auth))) => (client_id.as_ref(), Some(auth.as_ref())),
        (&Some(ref client_id), &None) => (client_id.as_ref(), None),
        _ => return Err(IssuerError::invalid(())),
    };

    let client = handler.client(&client_id).ok_or(
        IssuerError::unauthorized((), "basic"))?;
    client.check_authentication(auth).map_err(|_|
        IssuerError::unauthorized((), "basic"))?;

    match request.grant_type() {
        Some(ref cow) if cow == "authorization_code" => (),
        None => return Err(IssuerError::invalid(())),
        Some(_) => return Err(IssuerError::invalid(AccessTokenErrorType::UnsupportedGrantType)),
    };

    let code = request.code()
        .ok_or(IssuerError::invalid(()))?;
    let code = code.as_ref();

    let saved_params = match handler.extract(code) {
        None => return Err(IssuerError::invalid(())),
        Some(v) => v,
    };

    let redirect_uri = request.redirect_uri()
        .ok_or(IssuerError::invalid(()))?;
    let redirect_uri = redirect_uri.as_ref();

    if (saved_params.client_id.as_ref(), saved_params.redirect_uri.as_str()) != (client_id, redirect_uri) {
        return Err(IssuerError::invalid(AccessTokenErrorType::InvalidGrant))
    }

    if saved_params.until < Utc::now() {
        return Err(IssuerError::invalid((AccessTokenErrorType::InvalidGrant, "Grant expired")).into())
    }

    let mut code_extensions = saved_params.extensions;
    let mut access_extensions = Extensions::new();

    for extension_instance in extensions {
        let saved_extension = code_extensions.remove(extension_instance);
        match extension_instance.extend_access_token(request, saved_extension) {
            Err(_) =>  return Err(IssuerError::invalid(())),
            Ok(Some(extension)) => access_extensions.set(extension_instance, extension),
            Ok(None) => (),
        }
    }

    let token = handler.issue(Grant {
        client_id: saved_params.client_id,
        owner_id: saved_params.owner_id,
        redirect_uri: saved_params.redirect_uri,
        scope: saved_params.scope.clone(),
        until: Utc::now() + Duration::hours(1),
        extensions: access_extensions,
    }).map_err(|()| IssuerError::invalid((
        AccessTokenErrorType::InvalidRequest,
        "Failed to generate issued tokens"
    )))?;

    Ok(BearerToken{ 0: token, 1: saved_params.scope.to_string() })
}

/// Defines actions for the response to an access token request.
pub enum IssuerError {
    /// The token did not represent a valid token.
    Invalid(ErrorDescription),

    /// The client did not properly authorize itself.
    Unauthorized(ErrorDescription, String),
}

/// Simple wrapper around AccessTokenError to imbue the type with addtional json functionality. In
/// addition this enforces backend specific behaviour for obtaining or handling the access error.
pub struct ErrorDescription {
    error: AccessTokenError,
}

type AccessTokenResult<T> = Result<T, IssuerError>;

impl IssuerError {
    fn invalid<Mod>(modifier: Mod) -> IssuerError where Mod: AccessTokenErrorExt {
        IssuerError::Invalid(ErrorDescription{
            error: AccessTokenError::with((AccessTokenErrorType::InvalidRequest, modifier))
        })
    }

    fn unauthorized<Mod>(modifier: Mod, authtype: &str) -> IssuerError where Mod: AccessTokenErrorExt {
        IssuerError::Unauthorized(
            ErrorDescription{error: AccessTokenError::with((AccessTokenErrorType::InvalidClient, modifier))},
            authtype.to_string())
    }
}

impl ErrorDescription {
    /// Convert the error into a json string, viable for being sent over a network with
    /// `application/json` encoding.
    pub fn to_json(self) -> String {
        use std::iter::IntoIterator;
        use std::collections::HashMap;
        let asmap = self.error.into_iter()
            .map(|(k, v)| (k.to_string(), v.into_owned()))
            .collect::<HashMap<String, String>>();
        serde_json::to_string(&asmap).unwrap()
    }
}

/// Represents an access token, a refresh token and the associated scope for serialization.
pub struct BearerToken(IssuedToken, String);

impl BearerToken {
    /// Convert the token into a json string, viable for being sent over a network with
    /// `application/json` encoding.
    pub fn to_json(self) -> String {
        let remaining = self.0.until.signed_duration_since(Utc::now());
        let kvmap: HashMap<_, _> = vec![
            ("access_token", self.0.token),
            ("refresh_token", self.0.refresh),
            ("token_type", "bearer".to_string()),
            ("expires_in", remaining.num_seconds().to_string()),
            ("scope", self.1)].into_iter().collect();
        serde_json::to_string(&kvmap).unwrap()
    }
}
