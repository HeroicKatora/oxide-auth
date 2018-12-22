/// Helper for ad-hoc authorization endpoints needs.
///
/// Implements a simple struct with public members `Generic` that provides a common basis with an
/// `Endpoint` implementation. Tries to implement the least amount of policies and logic while
/// providing the biggest possible customizability (in that order).
use primitives::authorizer::Authorizer;
use primitives::issuer::Issuer;
use primitives::registrar::Registrar;
use primitives::scope::Scope;

use code_grant::endpoint::{AccessTokenFlow, Endpoint, OwnerConsent, OwnerSolicitor, OAuthError, PreGrant, ResponseKind, WebRequest};

/// Errors either caused by the underlying web types or the library.
#[derive(Debug)]
pub enum Error<W: WebRequest> {
    /// An operation on a request or response failed.
    ///
    /// Typically, this should be represented as a `500–Internal Server Error`.
    Web(W::Error),

    /// Some part of the library signaled failure.
    ///
    /// No response has been generated, and in some cases doing so should be done with care or
    /// under the consideration of an attacker currently trying to abuse the system.
    OAuth(OAuthError),
}

/// A rather basic `Endpoint` implementation.
///
/// Substitue all parts that are not provided with the marker struct `Vacant`. This will at least
/// ensure that no security properties are violated. Some flows may be unavailable when some
/// primitives are missing. See `AccessTokenFlow`, `AuthorizationFlow`, `ResourceFlow` in
/// `code_grant::endpoint` for more details.
///
/// Included types are assumed to be implemented independently, with no major connections. All
/// attributes are public, so there is no inner invariant. The maintained invariants are already
/// statically encoded in the type coices.
pub struct Generic<R, A, I, S, C> {
    /// The registrar implementation of `Vacant`.
    pub registrar: R,

    /// The authorizer implementation of `Vacant`.
    pub authorizer: A,

    /// The issuer implementation of `Vacant`.
    pub issuer: I,

    /// A solicitor implementation fit for the request types or `Vacant`.
    pub solicitor: S,
    
    /// Determine scopes for the request types or `Vacant`.
    pub scopes: C,
}

/// Marker struct if some primitive is not provided.
///
/// Used in place of other primitives when those are not provided. The exact semantics depend on
/// the primitive.
///
/// ## Registrar, Authorizer, Issuer
///
/// Statically ensures to the `Generic` endpoint that no such primitive has been provided. Using
/// the endpoint for flows that need such primitives will fail during the preparation phase. This
/// returns `Option::None` in the implementations for `OptRef<T>`, `OptRegistrar`, `OptAuthorizer`,
/// `OptIssuer`.
///
/// ## OwnerSolicitor
///
/// A solicitor denying all requests. This is the 'safe' default solicitor, remember to configure
/// your own solicitor when you actually need to use it.
///
/// In contrast to the other primitives, this can not be solved as something such as
/// `OptSolicitor<W>` since there is no current stable way to deny other crates from implementing
/// `OptSolicitor<WR>` for some `WR` from that other crate. Thus, the compiler must assume that
/// `None` may in fact implement some solicitor and this makes it impossible to implement as an
/// optional reference trait for all solicitors in one way but in a different way for the `None`
/// solicitor.
///
/// ## Scopes
///
/// Returns an empty list of scopes, effictively denying all requests since at least one scope
/// needs to be fulfilled by token to gain access.
///
/// See [OwnerSolicitor](#OwnerSolicitor) for discussion on why this differs from the other
/// primitives.
pub struct Vacant;

/// Like `AsRef` but with an optional result.
///
/// You are not supposed to need to implement this.
/// 
/// Keep in mind that using some `T` that is a trait will get sugared to `T + 'static` in the
/// transformation to trait object, if no explicit bound is given.
pub trait OptRef<T: ?Sized> {
    /// A reference as `T` or `Option::None`.
    fn opt_ref(&self) -> Option<&T>;
}

/// Like `AsRef<Registrar +'_>` but in a way that is expressible.
///
/// You are not supposed to need to implement this.
///
/// The difference to `AsRef` is that the `std` trait implies the trait lifetime bound be
/// independent of the lifetime of `&self`. This leads to some annoying implementation constraints,
/// similar to how you can not implement an `Iterator<&'_ mut Item>` whose items (i.e. `next`
/// method) borrow the iterator. Only in this case the lifetime trouble is hidden behind the
/// automatically inferred lifetime, as `AsRef<Trait>` actually refers to 
/// `AsRef<(Trait + 'static)`. But `as_ref` should have unsugared signature:
///
/// > `fn opt_ref<'a>(&'a self) -> Option<&'a (Trait + 'a)>`
///
/// Unfortunately, the `+ 'a` combiner can only be applied to traits, so we need a separate `OptX`
/// trait for each trait for which we want to make use of such a function, afaik. If you have
/// better ideas, I'll be grateful for opening an item on the Issue tracker.
pub trait OptRegistrar {
    /// Reference this as a `Registrar` or `Option::None`.
    fn opt_ref(&self) -> Option<&Registrar>;
}

/// Like `AsMut<Authorizer +'_>` but in a way that is expressible.
///
/// You are not supposed to need to implement this.
///
/// The difference to `AsMut` is that the `std` trait implies the trait lifetime bound be
/// independent of the lifetime of `&self`. This leads to some annoying implementation constraints,
/// similar to how you can not implement an `Iterator<&'_ mut Item>` whose items (i.e. `next`
/// method) borrow the iterator. Only in this case the lifetime trouble is hidden behind the
/// automatically inferred lifetime, as `AsMut<Trait>` actually refers to 
/// `AsMut<(Trait + 'static)`. But `opt_mut` should have unsugared signature:
///
/// > `fn opt_mut<'a>(&'a mut self) -> Option<&'a mut (Trait + 'a)>`
///
/// Unfortunately, the `+ 'a` combiner can only be applied to traits, so we need a separate `OptX`
/// trait for each trait for which we want to make use of such a function, afaik. If you have
/// better ideas, I'll be grateful for opening an item on the Issue tracker.
pub trait OptAuthorizer {
    /// Reference this mutably as an `Authorizer` or `Option::None`.
    fn opt_mut(&mut self) -> Option<&mut Authorizer>;
}

/// Like `AsMut<Issuer +'_>` but in a way that is expressible.
///
/// You are not supposed to need to implement this.
///
/// The difference to `AsMut` is that the `std` trait implies the trait lifetime bound be
/// independent of the lifetime of `&self`. This leads to some annoying implementation constraints,
/// similar to how you can not implement an `Iterator<&'_ mut Item>` whose items (i.e. `next`
/// method) borrow the iterator. Only in this case the lifetime trouble is hidden behind the
/// automatically inferred lifetime, as `AsMut<Trait>` actually refers to 
/// `AsMut<(Trait + 'static)`. But `opt_mut` should have unsugared signature:
///
/// > `fn opt_mut<'a>(&'a mut self) -> Option<&'a mut (Trait + 'a)>`
///
/// Unfortunately, the `+ 'a` combiner can only be applied to traits, so we need a separate `OptX`
/// trait for each trait for which we want to make use of such a function, afaik. If you have
/// better ideas, I'll be grateful for opening an item on the Issue tracker.
pub trait OptIssuer {
    /// Reference this mutably as an `Issuer` or `Option::None`.
    fn opt_mut(&mut self) -> Option<&mut Issuer>;
}

type AccessToken<'a> = Generic<&'a (Registrar + 'a), &'a mut (Authorizer + 'a), &'a mut (Issuer + 'a), Vacant, Vacant>;

/// Create an ad-hoc access token flow.
///
/// Since all necessary primitives are expected in the function syntax, this is guaranteed to never
/// fail or panic, compared to preparing one with `AccessTokenFlow`. 
///
/// But this is not as versatile and extensible, so it should be used with care.  The fact that it
/// only takes references is a conscious choice to maintain forwards portability while encouraging
/// the transition to custom `Endpoint` implementations instead.
pub fn access_token_flow<'a, W>(registrar: &'a Registrar, authorizer: &'a mut Authorizer, issuer: &'a mut Issuer) 
    -> AccessTokenFlow<AccessToken<'a>, W>
    where W: WebRequest, W::Response: Default
{
    let flow = AccessTokenFlow::prepare(Generic {
        registrar,
        authorizer,
        issuer,
        solicitor: Vacant,
        scopes: Vacant,
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

impl OptRegistrar for Vacant {
    fn opt_ref(&self) -> Option<&Registrar> {
        Option::None
    }
}

impl OptAuthorizer for Vacant {
    fn opt_mut(&mut self) -> Option<&mut Authorizer> {
        Option::None
    }
}

impl OptIssuer for Vacant {
    fn opt_mut(&mut self) -> Option<&mut Issuer> {
        Option::None
    }
}

impl<W: WebRequest> OwnerSolicitor<W> for Vacant {
    fn check_consent(&mut self, _: &mut W, _: &PreGrant) -> OwnerConsent<W::Response> {
        OwnerConsent::Denied
    }
}

impl OptRef<[Scope]> for Vacant {
    fn opt_ref(&self) -> Option<&[Scope]> {
        Option::None
    }
}
