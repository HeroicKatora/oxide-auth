use std::borrow::Cow;
use std::collections::HashMap;

use chrono::{Duration, Utc};
use serde_json;

use code_grant::error::{AccessTokenError, AccessTokenErrorType, AccessTokenErrorExt};
use primitives::authorizer::Authorizer;
use primitives::issuer::{IssuedToken, Issuer};
use primitives::grant::{Extension as ExtensionData, Extensions, Grant, GrantExtension};
use primitives::registrar::Registrar;

/// Trait based retrieval of parameters necessary for access token request handling.
pub trait Request {
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

/// An extension reacting to an access token request with a provided access token.
pub trait Extension: GrantExtension {
    /// Process an access token request, utilizing the extensions stored data if any.
    ///
    /// The semantics are equivalent to that of `CodeExtension` except that any data which was
    /// returned as a response to the authorization code request is provided as an additional
    /// parameter.
    fn extend_access_token(&self, &Request, Option<ExtensionData>) 
        -> std::result::Result<Option<ExtensionData>, ()>;
}

/// Required functionality to respond to access token requests.
///
/// Each method will only be invoked exactly once when processing a correct and authorized request,
/// and potentially less than once when the request is faulty.  These methods should be implemented
/// by internally using `primitives`, as it is implemented in the `frontend` module.
pub trait Endpoint {
    /// Get the client corresponding to some id.
    fn registrar(&self) -> &Registrar;

    /// Get the authorizer from which we can recover the authorization.
    fn authorizer(&mut self) -> &mut Authorizer;

    /// Return the issuer instance to create the access token.
    fn issuer(&mut self) -> &mut Issuer;

    /// An iterator over the used extensions.
    fn extensions(&self) -> Box<Iterator<Item=&Extension>>;
}

/// Try to redeem an authorization code.
pub fn access_token(handler: &mut Endpoint, request: &Request) -> Result<BearerToken> {
    if !request.valid() {
        return Err(Error::invalid(()))
    }

    let authorization = request.authorization();
    let client_id = request.client_id();
    let (client_id, auth): (&str, Option<&[u8]>) = match (&client_id, &authorization) {
        (&None, &Some((ref client_id, ref auth))) => (client_id.as_ref(), Some(auth.as_ref())),
        (&Some(ref client_id), &None) => (client_id.as_ref(), None),
        _ => return Err(Error::invalid(())),
    };

    handler.registrar()
        .client(&client_id)
        .ok_or(Error::unauthorized((), "basic"))?
        .check_authentication(auth)
        .map_err(|_| Error::unauthorized((), "basic"))?;

    match request.grant_type() {
        Some(ref cow) if cow == "authorization_code" => (),
        None => return Err(Error::invalid(())),
        Some(_) => return Err(Error::invalid(AccessTokenErrorType::UnsupportedGrantType)),
    };

    let code = request
        .code()
        .ok_or(Error::invalid(()))?;
    let code = code.as_ref();

    let saved_params = match handler.authorizer().extract(code) {
        None => return Err(Error::invalid(())),
        Some(v) => v,
    };

    let redirect_uri = request
        .redirect_uri()
        .ok_or(Error::invalid(()))?;
    let redirect_uri = redirect_uri.as_ref();

    if (saved_params.client_id.as_ref(), saved_params.redirect_uri.as_str()) != (client_id, redirect_uri) {
        return Err(Error::invalid(AccessTokenErrorType::InvalidGrant))
    }

    if saved_params.until < Utc::now() {
        return Err(Error::invalid((AccessTokenErrorType::InvalidGrant, "Grant expired")).into())
    }

    let mut code_extensions = saved_params.extensions;
    let mut access_extensions = Extensions::new();

    for extension_instance in handler.extensions() {
        let saved_extension = code_extensions.remove(&extension_instance);
        match extension_instance.extend_access_token(request, saved_extension) {
            Err(_) =>  return Err(Error::invalid(())),
            Ok(Some(extension)) => access_extensions.set(&extension_instance, extension),
            Ok(None) => (),
        }
    }

    let token = handler.issuer().issue(Grant {
        client_id: saved_params.client_id,
        owner_id: saved_params.owner_id,
        redirect_uri: saved_params.redirect_uri,
        scope: saved_params.scope.clone(),
        until: Utc::now() + Duration::hours(1),
        extensions: access_extensions,
    }).map_err(|()| Error::invalid((
        AccessTokenErrorType::InvalidRequest,
        "Failed to generate issued tokens"
    )))?;

    Ok(BearerToken{ 0: token, 1: saved_params.scope.to_string() })
}

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
    Primitive(PrimitiveError),

    /// The operation failed in such a way that it would not be wise for the
    /// connected client to know a more diverse reason.
    Internal,
}

/// The endpoint should have enough control over its primitives to find
/// out what has gone wrong, e.g. they may externall supply error 
/// information.
/// 
/// In this case, all previous results returned by the primitives are
/// included in the return value. Through this mechanism, one can
/// accomodate async handlers by implementing a sync-based result cache
/// that is filled with these partial values. In case only parts of the
/// outstanding futures, invoked during internal calls, are ready the
/// cache can be refilled through the error eliminating polls to already
/// sucessful futures.
///
/// Note that `token` is not included in this list, since the handler
/// can never fail after supplying a token to the backend.
pub struct PrimitiveError {
    /// The already extracted grant.
    ///
    /// You may reuse this, or more precisely you must to fulfill this exact request in case of
    /// an error recovery attempt.
    pub grant: Option<Grant>,

    /// The extensions that were computed.
    pub extensions: Option<Extensions>,
}

/// Simple wrapper around AccessTokenError to imbue the type with addtional json functionality. In
/// addition this enforces backend specific behaviour for obtaining or handling the access error.
pub struct ErrorDescription {
    error: AccessTokenError,
}

type Result<T> = std::result::Result<T, Error>;

impl Error {
    fn invalid<Mod>(modifier: Mod) -> Error where Mod: AccessTokenErrorExt {
        Error::Invalid(ErrorDescription{
            error: AccessTokenError::with((AccessTokenErrorType::InvalidRequest, modifier))
        })
    }

    fn unauthorized<Mod>(modifier: Mod, authtype: &str) -> Error where Mod: AccessTokenErrorExt {
        Error::Unauthorized(
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
