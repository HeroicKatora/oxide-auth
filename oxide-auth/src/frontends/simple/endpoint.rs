//! An ad-hoc endpoint.
//!
//! Provides a simple struct with public members – [`Generic`] – that implements the central
//! [`Endpoint`] trait implementation. Tries to implement the least amount of policies and logic
//! while providing the biggest possible customizability (priority in this order).
//!
//! [`Generic`]: ./struct.Generic.html
//! [`Endpoint`]: ../../endpoint/trait.Endpoint.html

use crate::primitives::authorizer::Authorizer;
use crate::primitives::issuer::Issuer;
use crate::primitives::registrar::Registrar;
use crate::primitives::scope::Scope;

use crate::endpoint::{AccessTokenFlow, AuthorizationFlow, ResourceFlow, RefreshFlow, ClientCredentialsFlow};
use crate::endpoint::{Endpoint, Extension, OAuthError, PreGrant, Template, Scopes};
use crate::endpoint::{OwnerConsent, OwnerSolicitor, Solicitation};
use crate::endpoint::WebRequest;

use std::marker::PhantomData;

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

/// A rather basic [`Endpoint`] implementation.
///
/// Substitue all parts that are not provided with the marker struct [`Vacant`]. This will at least
/// ensure that no security properties are violated. Some flows may be unavailable when some
/// primitives are missing. See [`AuthorizationFlow`], [`AccessTokenFlow`], [`ResourceFlow`] for
/// more details.
///
/// Included types are assumed to be implemented independently, with no major connections. All
/// attributes are public, so there is no inner invariant.
///
/// ## Usage
///
/// You should prefer this implementation when there are special requirements for your [`Endpoint`]
/// implementation, or it is created ad-hoc. It also does some static type checking on dedicated
/// methods to ensure that the creation of specific flows succeeds. You should prefer
/// `authorization_flow`, `access_token_flow`, and `resource_flow` over the erroring preparation
/// methods in [`AuthorizationFlow`], [`AccessTokenFlow`], and [`ResourceFlow`] respectively.
///
/// This should not be used when you special interacting primitives are used, that originate from
/// outside this library. For example if you intend for your [`Scopes`] to be dynamically generated
/// from a list of registered clients, its likely cleaner to provide your own [`Endpoint`]
/// implementation instead.
///
/// ## Example
///
/// Here is an example where a `Generic` is used to set up an endpoint that is filled with the
/// minimal members to be useable for an [`AccessTokenFlow`].
///
/// ```
/// # extern crate oxide_auth;
/// # use oxide_auth::frontends::simple::endpoint::Vacant;
/// # use oxide_auth::frontends::simple::endpoint::Generic;
/// use oxide_auth::endpoint::{AccessTokenFlow, Endpoint, WebRequest};
/// use oxide_auth::primitives::{
///     authorizer::AuthMap,
///     generator::RandomGenerator,
///     issuer::TokenMap,
///     registrar::ClientMap,
/// };
///
/// fn access_token_endpoint<R: WebRequest>() -> AccessTokenFlow<impl Endpoint<R>, R>
///     where R::Response: Default,
/// {
///     let endpoint = Generic {
///         authorizer: AuthMap::new(RandomGenerator::new(16)),
///         registrar: ClientMap::new(),
///         issuer: TokenMap::new(RandomGenerator::new(16)),
///         scopes: Vacant,
///         solicitor: Vacant,
///         response: Vacant,
///     };
///     endpoint.access_token_flow()
/// }
/// ```
///
/// [`Endpoint`]: ../../../endpoint/trait.Endpoint.html
/// [`Vacant`]: struct.Vacant.html
/// [`AuthorizationFlow`]: ../../../endpoint/struct.AuthorizationFlow.html
/// [`AccessTokenFlow`]: ../../../endpoint/struct.AccessTokenFlow.html
/// [`ResourceFlow`]: ../../../endpoint/struct.ResourceFlow.html
/// [`ResourceFlow`]: ../../../endpoint/trait.Scopes.html
pub struct Generic<R, A, I, S = Vacant, C = Vacant, L = Vacant> {
    /// The registrar implementation, or `Vacant` if it is not necesary.
    pub registrar: R,

    /// The authorizer implementation, or `Vacant` if it is not necesary.
    pub authorizer: A,

    /// The issuer implementation, or `Vacant` if it is not necesary.
    pub issuer: I,

    /// A solicitor implementation fit for the request types, or `Vacant` if it is not necesary.
    pub solicitor: S,

    /// Determine scopes for the request types, or `Vacant` if this does not protect resources.
    pub scopes: C,

    /// Creates responses, or `Vacant` if `Default::default` is applicable.
    pub response: L,
}

/// A simple wrapper around an Endpoint to change it's error type into anything `Into`-able.
pub struct ErrorInto<E, Error>(E, PhantomData<Error>);

impl<E, Error> ErrorInto<E, Error> {
    /// Create a new ErrorInto wrapping the supplied endpoint.
    pub fn new(endpoint: E) -> Self {
        ErrorInto(endpoint, PhantomData)
    }
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

/// A simple wrapper for functions and lambdas to be used as solicitors.
pub struct FnSolicitor<F>(pub F);

/// Use a predetermined grant and owner as solicitor.
///
/// Convenience wrapper when the owner and her/his consent to a grant can be identified without
/// further inspecting the request executing the flow. This may be the case for `WebRequest`
/// implementations extracted from an original http request. This solicitor is obviously mostly
/// useful for one-shot endpoints.
pub struct ApprovedGrant {
    /// The owner that approves of the grant.
    pub owner: String,

    /// The exact approved grant.
    pub grant: PreGrant,
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
    fn opt_ref(&self) -> Option<&dyn Registrar>;
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
    fn opt_mut(&mut self) -> Option<&mut dyn Authorizer>;
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
    fn opt_mut(&mut self) -> Option<&mut dyn Issuer>;
}

/// Independent component responsible for instantiating responses.
pub trait ResponseCreator<W: WebRequest> {
    /// Will only be called at most once per flow execution.
    fn create(&mut self, request: &mut W, kind: Template) -> W::Response;
}

type Authorization<'a, W> = Generic<
    &'a (dyn Registrar + 'a),
    &'a mut (dyn Authorizer + 'a),
    Vacant,
    &'a mut (dyn OwnerSolicitor<W> + 'a),
    Vacant,
    Vacant,
>;
type AccessToken<'a> = Generic<
    &'a (dyn Registrar + 'a),
    &'a mut (dyn Authorizer + 'a),
    &'a mut (dyn Issuer + 'a),
    Vacant,
    Vacant,
    Vacant,
>;
type ClientCredentials<'a, W> = Generic<
    &'a (dyn Registrar + 'a),
    Vacant,
    &'a mut (dyn Issuer + 'a),
    &'a mut (dyn OwnerSolicitor<W> + 'a),
    Vacant,
    Vacant,
>;
type Refresh<'a> =
    Generic<&'a (dyn Registrar + 'a), Vacant, &'a mut (dyn Issuer + 'a), Vacant, Vacant, Vacant>;
type Resource<'a> = Generic<Vacant, Vacant, &'a mut (dyn Issuer + 'a), Vacant, &'a [Scope], Vacant>;

/// Create an ad-hoc authorization flow.
///
/// Since all necessary primitives are expected in the function syntax, this is guaranteed to never
/// fail or panic, compared to preparing one with `AuthorizationFlow`.
///
/// But this is not as versatile and extensible, so it should be used with care.  The fact that it
/// only takes references is a conscious choice to maintain forwards portability while encouraging
/// the transition to custom `Endpoint` implementations instead.
pub fn authorization_flow<'a, W>(
    registrar: &'a dyn Registrar, authorizer: &'a mut dyn Authorizer,
    solicitor: &'a mut dyn OwnerSolicitor<W>,
) -> AuthorizationFlow<Authorization<'a, W>, W>
where
    W: WebRequest,
    W::Response: Default,
{
    let flow = AuthorizationFlow::prepare(Generic {
        registrar,
        authorizer,
        issuer: Vacant,
        solicitor,
        scopes: Vacant,
        response: Vacant,
    });

    match flow {
        Err(_) => unreachable!(),
        Ok(flow) => flow,
    }
}

/// Create an ad-hoc access token flow.
///
/// Since all necessary primitives are expected in the function syntax, this is guaranteed to never
/// fail or panic, compared to preparing one with `AccessTokenFlow`.
///
/// But this is not as versatile and extensible, so it should be used with care.  The fact that it
/// only takes references is a conscious choice to maintain forwards portability while encouraging
/// the transition to custom `Endpoint` implementations instead.
pub fn access_token_flow<'a, W>(
    registrar: &'a dyn Registrar, authorizer: &'a mut dyn Authorizer, issuer: &'a mut dyn Issuer,
) -> AccessTokenFlow<AccessToken<'a>, W>
where
    W: WebRequest,
    W::Response: Default,
{
    let flow = AccessTokenFlow::prepare(Generic {
        registrar,
        authorizer,
        issuer,
        solicitor: Vacant,
        scopes: Vacant,
        response: Vacant,
    });

    match flow {
        Err(_) => unreachable!(),
        Ok(flow) => flow,
    }
}

/// Create an ad-hoc client credentials flow.
///
/// Since all necessary primitives are expected in the function syntax, this is guaranteed to never
/// fail or panic, compared to preparing one with `ClientCredentialsFlow`.
///
/// But this is not as versatile and extensible, so it should be used with care.  The fact that it
/// only takes references is a conscious choice to maintain forwards portability while encouraging
/// the transition to custom `Endpoint` implementations instead.
pub fn client_credentials_flow<'a, W>(
    registrar: &'a dyn Registrar, issuer: &'a mut dyn Issuer, solicitor: &'a mut dyn OwnerSolicitor<W>,
) -> ClientCredentialsFlow<ClientCredentials<'a, W>, W>
where
    W: WebRequest,
    W::Response: Default,
{
    let flow = ClientCredentialsFlow::prepare(Generic {
        registrar,
        authorizer: Vacant,
        issuer,
        solicitor,
        scopes: Vacant,
        response: Vacant,
    });

    match flow {
        Err(_) => unreachable!(),
        Ok(flow) => flow,
    }
}

/// Create an ad-hoc resource flow.
///
/// Since all necessary primitives are expected in the function syntax, this is guaranteed to never
/// fail or panic, compared to preparing one with `ResourceFlow`.
///
/// But this is not as versatile and extensible, so it should be used with care.  The fact that it
/// only takes references is a conscious choice to maintain forwards portability while encouraging
/// the transition to custom `Endpoint` implementations instead.
pub fn resource_flow<'a, W>(
    issuer: &'a mut dyn Issuer, scopes: &'a [Scope],
) -> ResourceFlow<Resource<'a>, W>
where
    W: WebRequest,
    W::Response: Default,
{
    let flow = ResourceFlow::prepare(Generic {
        registrar: Vacant,
        authorizer: Vacant,
        issuer,
        solicitor: Vacant,
        scopes,
        response: Vacant,
    });

    match flow {
        Err(_) => unreachable!(),
        Ok(flow) => flow,
    }
}

/// Create an ad-hoc refresh flow.
///
/// Since all necessary primitives are expected in the function syntax, this is guaranteed to never
/// fail or panic, compared to preparing one with `ResourceFlow`.
///
/// But this is not as versatile and extensible, so it should be used with care.  The fact that it
/// only takes references is a conscious choice to maintain forwards portability while encouraging
/// the transition to custom `Endpoint` implementations instead.
pub fn refresh_flow<'a, W>(
    registrar: &'a dyn Registrar, issuer: &'a mut dyn Issuer,
) -> RefreshFlow<Refresh<'a>, W>
where
    W: WebRequest,
    W::Response: Default,
{
    let flow = RefreshFlow::prepare(Generic {
        registrar,
        authorizer: Vacant,
        issuer,
        solicitor: Vacant,
        scopes: Vacant,
        response: Vacant,
    });

    match flow {
        Err(_) => unreachable!(),
        Ok(flow) => flow,
    }
}

impl<R, A, I, O, C, L> Generic<R, A, I, O, C, L> {
    /// Change the used solicitor.
    pub fn with_solicitor<N>(self, new_solicitor: N) -> Generic<R, A, I, N, C, L> {
        Generic {
            registrar: self.registrar,
            authorizer: self.authorizer,
            issuer: self.issuer,
            solicitor: new_solicitor,
            scopes: self.scopes,
            response: self.response,
        }
    }

    /// Change the used scopes.
    pub fn with_scopes<S>(self, new_scopes: S) -> Generic<R, A, I, O, S, L> {
        Generic {
            registrar: self.registrar,
            authorizer: self.authorizer,
            issuer: self.issuer,
            solicitor: self.solicitor,
            scopes: new_scopes,
            response: self.response,
        }
    }

    /// Create an authorization flow.
    ///
    /// Opposed to `AuthorizationFlow::prepare` this statically ensures that the construction
    /// succeeds.
    pub fn authorization_flow<W: WebRequest>(self) -> AuthorizationFlow<Self, W>
    where
        Self: Endpoint<W>,
        R: Registrar,
        A: Authorizer,
    {
        match AuthorizationFlow::prepare(self) {
            Ok(flow) => flow,
            Err(_) => unreachable!(),
        }
    }

    /// Create an access token flow.
    ///
    /// Opposed to `AccessTokenFlow::prepare` this statically ensures that the construction
    /// succeeds.
    pub fn access_token_flow<W: WebRequest>(self) -> AccessTokenFlow<Self, W>
    where
        Self: Endpoint<W>,
        R: Registrar,
        A: Authorizer,
        I: Issuer,
    {
        match AccessTokenFlow::prepare(self) {
            Ok(flow) => flow,
            Err(_) => unreachable!(),
        }
    }

    /// Create a token refresh flow.
    ///
    /// Opposed to `RefreshFlow::prepare` this statically ensures that the construction succeeds.
    pub fn refresh_flow<W: WebRequest>(self) -> RefreshFlow<Self, W>
    where
        Self: Endpoint<W>,
        R: Registrar,
        I: Issuer,
    {
        match RefreshFlow::prepare(self) {
            Ok(flow) => flow,
            Err(_) => unreachable!(),
        }
    }

    /// Create a resource access flow.
    ///
    /// Opposed to `ResourceFlow::prepare` this statically ensures that the construction succeeds.
    pub fn resource_flow<W: WebRequest>(self) -> ResourceFlow<Self, W>
    where
        Self: Endpoint<W>,
        I: Issuer,
    {
        match ResourceFlow::prepare(self) {
            Ok(flow) => flow,
            Err(_) => unreachable!(),
        }
    }

    /// Check, statically, that this is an endpoint for some request.
    ///
    /// This is mainly a utility method intended for compilation and integration tests.
    pub fn assert<W: WebRequest>(self) -> Self
    where
        Self: Endpoint<W>,
    {
        self
    }
}

impl<W: WebRequest> Error<W> {
    /// Convert into a single error type.
    ///
    /// Note that the additional information whether the error occurred in the web components or
    /// during the flow needs to be implicitely contained in the types. Otherwise, this information
    /// is lost and you should use or provide a `From<Error<W>>` implementation instead. This
    /// method is still useful for frontends providing a standard error type that interacts with
    /// their web server library.
    pub fn pack<P>(self) -> P
    where
        OAuthError: Into<P>,
        W::Error: Into<P>,
    {
        match self {
            Error::Web(err) => err.into(),
            Error::OAuth(oauth) => oauth.into(),
        }
    }
}

impl<E, Error, W> Endpoint<W> for ErrorInto<E, Error>
where
    E: Endpoint<W>,
    E::Error: Into<Error>,
    W: WebRequest,
{
    type Error = Error;

    fn registrar(&self) -> Option<&dyn Registrar> {
        self.0.registrar()
    }

    fn authorizer_mut(&mut self) -> Option<&mut dyn Authorizer> {
        self.0.authorizer_mut()
    }

    fn issuer_mut(&mut self) -> Option<&mut dyn Issuer> {
        self.0.issuer_mut()
    }

    fn owner_solicitor(&mut self) -> Option<&mut dyn OwnerSolicitor<W>> {
        self.0.owner_solicitor()
    }

    fn scopes(&mut self) -> Option<&mut dyn Scopes<W>> {
        self.0.scopes()
    }

    fn response(&mut self, request: &mut W, kind: Template) -> Result<W::Response, Self::Error> {
        self.0.response(request, kind).map_err(Into::into)
    }

    fn error(&mut self, err: OAuthError) -> Self::Error {
        self.0.error(err).into()
    }

    fn web_error(&mut self, err: W::Error) -> Self::Error {
        self.0.web_error(err).into()
    }

    fn extension(&mut self) -> Option<&mut dyn Extension> {
        self.0.extension()
    }
}

impl<W, R, A, I, O, C, L> Endpoint<W> for Generic<R, A, I, O, C, L>
where
    W: WebRequest,
    R: OptRegistrar,
    A: OptAuthorizer,
    I: OptIssuer,
    O: OwnerSolicitor<W>,
    C: Scopes<W>,
    L: ResponseCreator<W>,
{
    type Error = Error<W>;

    fn registrar(&self) -> Option<&dyn Registrar> {
        self.registrar.opt_ref()
    }

    fn authorizer_mut(&mut self) -> Option<&mut dyn Authorizer> {
        self.authorizer.opt_mut()
    }

    fn issuer_mut(&mut self) -> Option<&mut dyn Issuer> {
        self.issuer.opt_mut()
    }

    fn owner_solicitor(&mut self) -> Option<&mut dyn OwnerSolicitor<W>> {
        Some(&mut self.solicitor)
    }

    fn scopes(&mut self) -> Option<&mut dyn Scopes<W>> {
        Some(&mut self.scopes)
    }

    fn response(&mut self, request: &mut W, kind: Template) -> Result<W::Response, Self::Error> {
        Ok(self.response.create(request, kind))
    }

    fn error(&mut self, err: OAuthError) -> Error<W> {
        Error::OAuth(err)
    }

    fn web_error(&mut self, err: W::Error) -> Error<W> {
        Error::Web(err)
    }
}

impl<T: Registrar> OptRegistrar for T {
    fn opt_ref(&self) -> Option<&dyn Registrar> {
        Some(self)
    }
}

impl<T: Authorizer> OptAuthorizer for T {
    fn opt_mut(&mut self) -> Option<&mut dyn Authorizer> {
        Some(self)
    }
}

impl<T: Issuer> OptIssuer for T {
    fn opt_mut(&mut self) -> Option<&mut dyn Issuer> {
        Some(self)
    }
}

impl OptRegistrar for Vacant {
    fn opt_ref(&self) -> Option<&dyn Registrar> {
        Option::None
    }
}

impl OptAuthorizer for Vacant {
    fn opt_mut(&mut self) -> Option<&mut dyn Authorizer> {
        Option::None
    }
}

impl OptIssuer for Vacant {
    fn opt_mut(&mut self) -> Option<&mut dyn Issuer> {
        Option::None
    }
}

impl<W: WebRequest> OwnerSolicitor<W> for Vacant {
    fn check_consent(&mut self, _: &mut W, _: Solicitation) -> OwnerConsent<W::Response> {
        OwnerConsent::Denied
    }
}

impl<W: WebRequest> Scopes<W> for Vacant {
    fn scopes(&mut self, _: &mut W) -> &[Scope] {
        const NO_SCOPES: [Scope; 0] = [];
        &NO_SCOPES
    }
}

impl<W, F> OwnerSolicitor<W> for FnSolicitor<F>
where
    W: WebRequest,
    F: FnMut(&mut W, Solicitation) -> OwnerConsent<W::Response>,
{
    fn check_consent(
        &mut self, request: &mut W, solicitation: Solicitation,
    ) -> OwnerConsent<W::Response> {
        (self.0)(request, solicitation)
    }
}

impl<W: WebRequest> OwnerSolicitor<W> for ApprovedGrant {
    /// Approve if the grant matches *exactly*.
    ///
    /// That is, `client_id`, `redirect_uri`, and `scope` of the pre-grant are all equivalent. In
    /// particular, the requested scope must match exactly not only be a subset of the approved
    /// scope.
    fn check_consent(&mut self, _: &mut W, solicitation: Solicitation) -> OwnerConsent<W::Response> {
        if &self.grant == solicitation.pre_grant() {
            OwnerConsent::Authorized(self.owner.clone())
        } else {
            OwnerConsent::Denied
        }
    }
}

impl<W: WebRequest> ResponseCreator<W> for Vacant
where
    W::Response: Default,
{
    fn create(&mut self, _: &mut W, _: Template) -> W::Response {
        Default::default()
    }
}

impl<W: WebRequest, F> ResponseCreator<W> for F
where
    F: FnMut() -> W::Response,
{
    fn create(&mut self, _: &mut W, _: Template) -> W::Response {
        self()
    }
}
