//! Retrieve a refreshed access token.
use std::borrow::Cow;
use std::collections::HashMap;

use chrono::{Duration, Utc};

use code_grant::error::{AccessTokenError, AccessTokenErrorType};
use primitives::grant::Grant;
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

/// The specific endpoin trait for refreshing.
///
/// Each method will only be invoked exactly once when processing a correct and authorized request,
/// and potentially less than once when the request is faulty.  These methods should be implemented
/// by internally using `primitives`, as it is implemented in the `frontend` module.
pub trait Endpoint {
    /// Authenticate the requesting confidential client.
    fn registrar(&self) -> &dyn Registrar;

    /// Recover and test the provided refresh token then issue new tokens.
    fn issuer(&mut self) -> &mut dyn Issuer;
}

/// Represents a bearer token, optional refresh token and the associated scope for serialization.
pub struct BearerToken(RefreshedToken, String);

/// An ongoing refresh request.
pub struct Refresh<'req> {
    state: RefreshState<'req>,
}

/// Inner state machine for refreshing.
enum RefreshState<'req> {
    /// The initial state.
    New {
        request: &'req dyn Request,
    },
    /// State we reach after the request has been validated.
    ///
    /// Next, the registrar must verify the authentication (authorization header).
    Authenticating {
        request: &'req dyn Request,
        client: Cow<'req, str>,
        passdata: Option<Cow<'req, [u8]>>,
        token: Cow<'req, str>,
    },
    /// State after authorization has passed, waiting on recovering the refresh token.
    Recovering {
        request: &'req dyn Request,
        /// The user the registrar verified.
        authenticated: Option<String>,
        token: Cow<'req, str>,
    },
    /// State after the token has been determined but no authenticated client was used. Need to
    /// potentially wait on grant-to-authorized-user-correspondence matching.
    CoAuthenticating {
        request: &'req dyn Request,
        /// The restored grant.
        grant: Grant,
        /// The refresh token of the grant.
        token: Cow<'req, str>,
    },
    /// State when we await the issuing of a refreshed token.
    Issuing {
        request: &'req dyn Request,
        /// The grant with the parameter set.
        grant: Grant,
        /// The refresh token of the grant.
        token: Cow<'req, str>,
    },
    /// State after an error occurred.
    Err(Error),
}

pub enum Input {
    /// Positively answer an authentication query.
    Authenticated,
    /// Negatively answer an authentication query.
    RegistrarError(RegistrarError),
    /// Provide the queried refresh token.
    Recovered(Option<Grant>),
    /// The refreshed token.
    Issued(RefreshedToken),
    /// The issuer failed internally.
    IssuerError,
    /// Advance without input as far as possible, or just retrieve the output again.
    None,
}

pub enum Output<'a> {
    /// The registrar should authenticate a client.
    Unauthenticated {
        client: &'a str,
        pass: Option<&'a [u8]>,
    },
    /// The issuer should try to recover a refresh token.
    RecoverRefresh(String),
    /// The issuer should issue a refreshed token.
    Refresh {
        token: &'a str,
        grant: Grant,
    },
    Ok(BearerToken),
    Err(Error),
}

/// Defines actions for the response to an access token request.
#[derive(Clone, Debug)]
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
/// Enables additional json functionality to generate a properly formatted response in the user of
/// this module.
#[derive(Clone, Debug)]
pub struct ErrorDescription {
    error: AccessTokenError,
}

type Result<T> = std::result::Result<T, Error>;

impl<'req> Refresh<'req> {
    pub fn new(request: &'req dyn Request) -> Self {
        Refresh {
            state: RefreshState::New { request },
        }
    }

    fn take(&mut self)  -> RefreshState<'req> {
        core::mem::replace(&mut self.state, RefreshState::Err(Error::Primitive))
    }

    pub fn next(&mut self, input: Input) -> Output<'_> {
        // Run the next state transition if we got the right input. Errors that happen will be
        // stored as a inescapable error state.
        match (self.take(), input) {
            (RefreshState::Err(error), _) => {
                self.state = RefreshState::Err(error.clone());
                Output::Err(error)
            },
            (RefreshState::New { request }, Input::None) => {
                self.state = initialize(request)
                    .unwrap_or_else(RefreshState::Err);
                self.output()
            },
            (RefreshState::Authenticating { request, client, passdata: _, token }, Input::Authenticated) => {
                self.state = authenticated(request, client, token);
                self.output()
            },
            (RefreshState::Recovering { request, authenticated, token }, Input::Recovered(grant)) => {
                self.state = recovered_refresh(request, authenticated, grant, token)
                    .unwrap_or_else(RefreshState::Err);
                self.output()
            },
            (RefreshState::CoAuthenticating { request, grant, token }, Input::Authenticated) => {
                self.state = co_authenticated(request, grant, token)
                    .unwrap_or_else(RefreshState::Err);
                self.output()
            },
            (RefreshState::Issuing { request, grant, token: _ }, Input::Issued(token)) => {
                // Ensure that this result is not duplicated.
                self.state = RefreshState::Err(Error::Primitive);
                Output::Ok(issued(request, grant, token))
            },
            (_, Input::None) => self.output(),
            (_, _) => {
                self.state = RefreshState::Err(Error::Primitive);
                self.output()
            }
        }
    }

    fn output(&self) -> Output<'_> {
        match &self.state {
            RefreshState::New { .. } => unreachable!("This state never produces output"),
            RefreshState::Authenticating { client, passdata, .. } 
                => Output::Unauthenticated { client, pass: passdata.as_ref().map(|cow| cow.as_ref()) },
            RefreshState::CoAuthenticating { grant, .. }
                => Output::Unauthenticated { client: &grant.client_id, pass: None },
            RefreshState::Recovering { token, .. }
                => Output::RecoverRefresh(token.clone().into_owned()),
            RefreshState::Issuing { token, grant, .. }
                => Output::Refresh { token, grant: grant.clone(), },
            RefreshState::Err(error) => Output::Err(error.clone()),
        }
    }
}

impl Input {
    pub fn take(&mut self) -> Self {
        core::mem::replace(self, Input::None)
    }
}

/// Try to get a refreshed access token.
///
/// This has four basic phases:
/// 1. Ensure the request is valid based on the basic requirements (includes required parameters)
/// 2. Check any included authentication
/// 3. Try to recover the refresh token
///     3.1. Check that it belongs to the authenticated client
///     3.2. If there was no authentication, assert token does not require authentication
///     3.3. Check the intrinsic validity (timestamp, scope)
/// 4. Query the backend for a renewed (bearer) token
pub fn refresh(handler: &mut dyn Endpoint, request: &dyn Request)
    -> Result<BearerToken> 
{
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
                    .map_err(|()| Error::Primitive)?;
                input = Input::Issued(refreshed);
            },
            Output::RecoverRefresh(token) => {
                let recovered = handler
                    .issuer()
                    .recover_refresh(&token)
                    .map_err(|()| Error::Primitive)?;
                input = Input::Recovered(recovered);
            },
            Output::Unauthenticated { client, pass } => {
                let _: () = handler
                    .registrar()
                    .check(client, pass)
                    .map_err(|err| match err {
                        RegistrarError::PrimitiveError => Error::Primitive,
                        RegistrarError::Unspecified => Error::unauthorized("basic"),
                    })?;
                input = Input::Authenticated;
            },
        }
    }
}

fn initialize(request: &dyn Request)
    -> Result<RefreshState>
{
    if !request.valid() {
        return Err(Error::invalid(AccessTokenErrorType::InvalidRequest))
    }

    // REQUIRED, so not having it makes it an invalid request.
    let token = request.refresh_token();
    let token = token.ok_or(Error::invalid(AccessTokenErrorType::InvalidRequest))?;

    // REQUIRED, otherwise invalid request.
    match request.grant_type() {
        Some(ref cow) if cow == "refresh_token" => (),
        None => return Err(Error::invalid(AccessTokenErrorType::InvalidRequest)),
        Some(_) => return Err(Error::invalid(AccessTokenErrorType::UnsupportedGrantType)),
    };

    match request.authorization() {
        Some((client, passdata)) => Ok(RefreshState::Authenticating {
            request,
            client,
            passdata: Some(passdata),
            token,
        }),
        None => Ok(RefreshState::Recovering { 
            request,
            token,
            authenticated: None,
        })
    }
}

fn authenticated<'req>(request: &'req dyn Request, client: Cow<'req, str>, token: Cow<'req, str>)
    -> RefreshState<'req>
{
    // Trivial, simply advance to recovering the token.
    RefreshState::Recovering {
        request,
        token,
        authenticated: Some(client.into_owned()),
    }
}

fn recovered_refresh<'req>(
    request: &'req dyn Request,
    authenticated: Option<String>,
    grant: Option<Grant>,
    token: Cow<'req, str>,
) -> Result<RefreshState<'req>> {
    let grant = grant
        // ... is invalid, ... (Section 5.2)
        .ok_or_else(|| Error::invalid(AccessTokenErrorType::InvalidGrant))?;

    // ... MUST ensure that the refresh token was issued to the authenticated client.
    match authenticated {
        Some(client) => {
            if grant.client_id.as_str() != client {
                // ... or was issued to another client (Section 5.2)
                // importantly, the client authentication itself was okay, so we don't respond with
                // Unauthorized but with BadRequest.
                Err(Error::invalid(AccessTokenErrorType::InvalidGrant))
            } else {
                validate(request, grant, token)
            }
        },
        
        // ... MUST require client authentication for confidential clients.
        //
        // We'll see if this was confidential by trying to auth with no passdata. If that fails,
        // then the client should have authenticated with header information.
        None => {
            Ok(RefreshState::CoAuthenticating {
                request,
                grant,
                token,
            })
        }
    }
}

fn co_authenticated<'req>(
    request: &'req dyn Request,
    grant: Grant,
    token: Cow<'req, str>,
) -> Result<RefreshState<'req>> {
    validate(request, grant, token)
}

fn validate<'req>(
    request: &'req dyn Request,
    grant: Grant,
    token: Cow<'req, str>,
) -> Result<RefreshState<'req>> {
    // .. is expired, revoked, ... (Section 5.2)
    if grant.until <= Utc::now() {
        return Err(Error::invalid(AccessTokenErrorType::InvalidGrant));
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
    let mut grant = grant;
    grant.scope = scope;
    grant.until = Utc::now() + Duration::hours(1);

    Ok(RefreshState::Issuing {
        request,
        grant,
        token,
    })
}

fn issued<'req>(
    _: &'req dyn Request,
    grant: Grant,
    token: RefreshedToken,
) -> BearerToken {
    BearerToken(token, grant.scope.to_string())
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

    /// Convert the error into a json string.
    ///
    /// The string may be the content of an `application/json` body for example.
    pub fn to_json(self) -> String {
        let asmap = self.error.into_iter()
            .map(|(k, v)| (k.to_string(), v.into_owned()))
            .collect::<HashMap<String, String>>();
        serde_json::to_string(&asmap).unwrap()
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
