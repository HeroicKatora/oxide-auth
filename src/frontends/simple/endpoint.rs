/// Helper for ad-hoc authorization endpoints needs.
///
/// Does not own any of its data and implements `Endpoint` only in so far as to be compatible for
/// creating an `AuthorizationFlow` instance.
use primitives::authorizer::Authorizer;
use primitives::issuer::Issuer;
use primitives::registrar::Registrar;
use primitives::scope::Scope;

use code_grant::endpoint::{AccessTokenFlow, Endpoint, OwnerConsent, OwnerSolicitor, OAuthError, PreGrant, ResponseKind, WebRequest};

#[derive(Debug)]
pub enum Error<W: WebRequest> {
    Web(W::Error),
    OAuth(OAuthError),
}

pub struct Generic<R, A, I, S, C> {
    pub registrar: R,
    pub authorizer: A,
    pub issuer: I,
    pub solicitor: S,
    pub scopes: C,
}

/// Marker struct if some primitive is not provided.
pub struct None;

/// A solicitor denying all requests.
///
/// This is the 'safe' default solicitor, remember to configure your own solicitor when you
/// actually need to use it.
///
/// In contrast to the other primitives, this can not be solved as something such as
/// `OptSolicitor<W>` since there is no current stable way to deny other crates from implementing
/// `OptSolicitor<WR>` for some `WR` from that other crate. Thus, the compiler must assume that
/// `None` may in fact implement some solicitor and this makes it impossible to implement as an
/// optional reference trait for all solicitors in one way but in a different way for the `None`
/// solicitor.
pub struct DenyAll;

/// Like `AsRef` but with an optional result.
pub trait OptRef<T: ?Sized> {
    fn opt_ref(&self) -> Option<&T>;
}

pub trait OptRegistrar {
    fn opt_ref(&self) -> Option<&Registrar>;
}

pub trait OptAuthorizer {
    fn opt_mut(&mut self) -> Option<&mut Authorizer>;
}

pub trait OptIssuer {
    fn opt_mut(&mut self) -> Option<&mut Issuer>;
}

type AccessToken<'a> = Generic<&'a (Registrar + 'a), &'a mut (Authorizer + 'a), &'a mut (Issuer + 'a), DenyAll, DenyAll>;

pub fn access_token_flow<'a, W>(registrar: &'a Registrar, authorizer: &'a mut Authorizer, issuer: &'a mut Issuer) 
    -> AccessTokenFlow<AccessToken<'a>, W>
    where W: WebRequest, W::Response: Default
{
    let flow = AccessTokenFlow::prepare(Generic {
        registrar,
        authorizer,
        issuer,
        solicitor: DenyAll,
        scopes: DenyAll,
    });

    match flow {
        Err(_) => unreachable!(),
        Ok(flow) => flow,
    }
}

impl<W, R, A, I, O, C> Endpoint<W> for Generic<R, A, I, O, C> 
where 
    W: WebRequest, 
    W::Response: Default,
    R: OptRegistrar,
    A: OptAuthorizer,
    I: OptIssuer,
    O: OwnerSolicitor<W>,
    C: OptRef<[Scope]>,
{
    type Error = Error<W>;

    fn registrar(&self) -> Option<&Registrar> {
        self.registrar.opt_ref()
    }

    fn authorizer_mut(&mut self) -> Option<&mut Authorizer> {
        self.authorizer.opt_mut()
    }

    fn issuer_mut(&mut self) -> Option<&mut Issuer> {
        self.issuer.opt_mut()
    }

    fn owner_solicitor(&mut self) -> Option<&mut OwnerSolicitor<W>> {
        Some(&mut self.solicitor)
    }

    fn scopes(&mut self, _: &mut W) -> &[Scope] {
        const NO_SCOPES: [Scope; 0] = [];
        self.scopes.opt_ref().unwrap_or(&NO_SCOPES[..])
    }

    fn response(&mut self, _: &mut W, _: ResponseKind) -> Result<W::Response, Self::Error> {
        Ok(W::Response::default())
    }

    fn error(&mut self, err: OAuthError) -> Error<W> {
        Error::OAuth(err)
    }

    fn web_error(&mut self, err: W::Error) -> Error<W> {
        Error::Web(err)
    }
}

impl<T: Registrar> OptRegistrar for T {
    fn opt_ref(&self) -> Option<&Registrar> {
        Some(self)
    }
}

impl<T: Authorizer> OptAuthorizer for T {
    fn opt_mut(&mut self) -> Option<&mut Authorizer> {
        Some(self)
    }
}

impl<T: Issuer> OptIssuer for T {
    fn opt_mut(&mut self) -> Option<&mut Issuer> {
        Some(self)
    }
}

impl OptRegistrar for None {
    fn opt_ref(&self) -> Option<&Registrar> {
        Option::None
    }
}

impl OptAuthorizer for None {
    fn opt_mut(&mut self) -> Option<&mut Authorizer> {
        Option::None
    }
}

impl OptIssuer for None {
    fn opt_mut(&mut self) -> Option<&mut Issuer> {
        Option::None
    }
}

impl<W: WebRequest> OwnerSolicitor<W> for DenyAll {
    fn check_consent(&mut self, _: &mut W, _: &PreGrant) -> OwnerConsent<W::Response> {
        OwnerConsent::Denied
    }
}

impl OptRef<[Scope]> for DenyAll {
    fn opt_ref(&self) -> Option<&[Scope]> {
        Option::None
    }
}
