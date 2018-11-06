use std::borrow::Cow;
use std::fmt;

use chrono::Utc;

use primitives::grant::Grant;
use primitives::scope::Scope;


/// Gives additional information about the reason for an access failure.
///
/// According to [rfc6750], this should not be returned if the client has not provided any
/// authentication information.
///
/// [rfc6750]: https://tools.ietf.org/html/rfc6750#section-3.1
#[derive(Debug)]
pub struct AccessFailure {
    /// The standard error code representation.
    pub code: Option<ErrorCode>,
}

/// Indicates the reason for access failure.
#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    /// The request did not have enough authorization data or was otherwise malformed.
    InvalidRequest,

    /// The provided authorization did not grant sufficient priviledges.
    InsufficientScope,

    /// The token is expired, revoked, malformed or otherwise does not meet expectations.
    InvalidToken,
}

/// Additional information provided for the WWW-Authenticate header.
#[derive(Debug)]
pub struct Authenticate {
    /// Information about which realm the credentials correspond to.
    pub realm: Option<String>,

    /// The required scope to access the resource.
    pub scope: Option<Scope>,
}

/// An error signalling the resource access was not permitted.
#[derive(Debug)]
pub enum AccessError {
    /// The client tried to access a resource but was not able to.
    AccessDenied {
        /// A specific cause for denying access.
        failure: AccessFailure,

        /// Information for the `Authenticate` header in the error response.
        authenticate: Authenticate,
    },

    /// The client did not provide any bearer authentication.
    NoAuthentication {
        /// Information for the `Authenticate` header in the error response.
        authenticate: Authenticate,
    },

    /// The request itself was malformed.
    InvalidRequest {
        /// Information for the `Authenticate` header in the error response.
        authenticate: Authenticate,
    },
}

type AccessResult<T> = Result<T, AccessError>;

/// Required request methods for deciding on the rights to access a protected resource.
pub trait GuardRequest {
    /// Received request might not be encoded correctly. This method gives implementors the chance
    /// to signal that a request was received but its encoding was generally malformed. If this is
    /// the case, then no other attribute will be queried. This method exists mainly to make
    /// frontends straightforward by not having them handle special cases for malformed requests.
    fn valid(&self) -> bool;

    /// The authorization used in the request.
    ///
    /// Expects the complete `Authorization` HTTP-header, including the qualification as `Bearer`.
    /// In case the client included multiple forms of authorization, this method MUST return None
    /// and the request SHOULD be marked as invalid.
    fn token(&self) -> Option<Cow<str>>;
}

/// Required functionality to respond to resource requests.
///
/// Each method will only be invoked exactly once when processing a correct and authorized request,
/// and potentially less than once when the request is faulty.  These methods should be implemented
/// by internally using `primitives`, as it is implemented in the `frontend` module.
pub trait GuardEndpoint {
    /// The list of possible scopes required by the resource endpoint.
    fn scopes(&self) -> &[Scope];

    /// Recover the grant corresponding to a bearer token.
    fn recover_token(&self, bearer: &str) -> Option<Grant>;
}

/// The result will indicate whether the resource access should be allowed or not.
pub fn protect(handler: &GuardEndpoint, req: &GuardRequest)
-> AccessResult<()> {
    let authenticate = Authenticate {
        realm: None,
        scope: handler.scopes().get(0).cloned(),
    };

    if !req.valid() {
        return Err(AccessError::InvalidRequest {
            authenticate
        });
    }

    let token = match req.token() {
        Some(token) => token,
        None => return Err(AccessError::NoAuthentication {
            authenticate,
        }),
    };

    let grant = match handler.recover_token(&token) {
        Some(grant) => grant,
        None => return Err(AccessError::AccessDenied {
            failure: AccessFailure {
                code: Some(ErrorCode::InvalidRequest),
            },
            authenticate,
        }),
    };

    if grant.until < Utc::now() {
        return Err(AccessError::AccessDenied {
            failure: AccessFailure {
                code: Some(ErrorCode::InvalidToken),
            },
            authenticate,
        });
    }

    // Test if any of the possible allowed scopes is included in the grant
    if !handler.scopes().iter()
        .any(|resource_scope| resource_scope.allow_access(&grant.scope)) {
        return Err(AccessError::AccessDenied {
            failure: AccessFailure {
                code: Some(ErrorCode::InsufficientScope),
            },
            authenticate,
        });
    }

    return Ok(())
}

impl ErrorCode {
    fn description(self) -> &'static str {
        match self {
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::InsufficientScope => "insufficient_scope",
            ErrorCode::InvalidToken => "invalid_token",
        }
    }
}

struct BearerHeader {
    content: String,
    first_option: bool,
}

impl BearerHeader {
    fn new() -> Self {
        BearerHeader {
            content: "Bearer".to_string(),
            first_option: true,
        }
    }

    fn add_option(&mut self, args: fmt::Arguments) {
        if self.first_option {
            self.content.push(' ');
        } else {
            self.content.push(',');
        }
        fmt::write(&mut self.content, args).unwrap();
    }

    fn finalize(self) -> String {
        self.content
    }
}

impl Authenticate {
    fn extend_header(self, header: &mut BearerHeader) {
        self.realm.map(|realm| header.add_option(format_args!("realm=\"{}\"", realm)));
        self.scope.map(|scope| header.add_option(format_args!("scope=\"{}\"", scope)));
    }
}

impl AccessFailure {
    fn extend_header(self, header: &mut BearerHeader) {
        self.code.map(|code| header.add_option(format_args!("error=\"{}\"", code.description())));
    }
}

impl AccessError {
    /// Convert the guard error into the content used in an WWW-Authenticate header.
    pub fn www_authenticate(self) -> String {
        let mut header = BearerHeader::new();
        match self {
            AccessError::AccessDenied { failure, authenticate, } => {
                failure.extend_header(&mut header);
                authenticate.extend_header(&mut header);
            },
            AccessError::NoAuthentication { authenticate, } => {
                authenticate.extend_header(&mut header);
            },
            AccessError::InvalidRequest { authenticate, } => {
                authenticate.extend_header(&mut header);
            },
        }
        header.finalize()
    }
}
