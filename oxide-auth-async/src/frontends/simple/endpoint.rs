use oxide_auth::{
    frontends::simple::endpoint::Error,
    endpoint::{
        Template, WebRequest, Scopes, OAuthError, OwnerConsent, PreGrant, Scope, OwnerSolicitor,
    },
};

use crate::{
    endpoint::{Endpoint, access_token::AccessTokenFlow},
    primitives::{Issuer, Registrar, Authorizer},
};

// type Refresh<'a> =
//     Generic<&'a (dyn Registrar + 'a), Vacant, &'a mut (dyn Issuer + 'a), Vacant, Vacant, Vacant>;

type AccessToken<'a> = Generic<
    &'a (dyn Registrar + 'a),
    &'a mut (dyn Authorizer + 'a),
    &'a mut (dyn Issuer + 'a),
    Vacant,
    Vacant,
    Vacant,
>;

pub struct Vacant;

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
    // Reference this mutably as an `Authorizer` or `Option::None`.
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
    // pub fn to_authorization<W: WebRequest>(self) -> AuthorizationFlow<Self, W>
    // where
    //     Self: Endpoint<W>,
    //     R: Registrar,
    //     A: Authorizer,
    // {
    //     match AuthorizationFlow::prepare(self) {
    //         Ok(flow) => flow,
    //         Err(_) => unreachable!(),
    //     }
    // }

    /// Create an access token flow.
    ///
    /// Opposed to `AccessTokenFlow::prepare` this statically ensures that the construction
    /// succeeds.
    pub fn to_access_token<W: WebRequest>(self) -> AccessTokenFlow<Self, W>
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

    // /// Create a token refresh flow.
    // ///
    // /// Opposed to `RefreshFlow::prepare` this statically ensures that the construction succeeds.
    // pub fn to_refresh<W: WebRequest>(self) -> RefreshFlow<Self, W>
    // where
    //     Self: Endpoint<W>,
    //     R: Registrar,
    //     I: Issuer,
    // {
    //     match RefreshFlow::prepare(self) {
    //         Ok(flow) => flow,
    //         Err(_) => unreachable!(),
    //     }
    // }

    // /// Create a resource access flow.
    // ///
    // /// Opposed to `ResourceFlow::prepare` this statically ensures that the construction succeeds.
    // pub fn to_resource<W: WebRequest>(self) -> ResourceFlow<Self, W>
    // where
    //     Self: Endpoint<W>,
    //     I: Issuer,
    // {
    //     match ResourceFlow::prepare(self) {
    //         Ok(flow) => flow,
    //         Err(_) => unreachable!(),
    //     }
    // }

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

    // fn owner_solicitor(&mut self) -> Option<&mut dyn OwnerSolicitor<W>> {
    //     Some(&mut self.solicitor)
    // }

    // fn scopes(&mut self) -> Option<&mut dyn Scopes<W>> {
    //     Some(&mut self.scopes)
    // }

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
    fn check_consent(&mut self, _: &mut W, _: &PreGrant) -> OwnerConsent<W::Response> {
        OwnerConsent::Denied
    }
}

impl<W: WebRequest> Scopes<W> for Vacant {
    fn scopes(&mut self, _: &mut W) -> &[Scope] {
        const NO_SCOPES: [Scope; 0] = [];
        &NO_SCOPES
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

// /// Create an ad-hoc access token flow.
// ///
// /// Since all necessary primitives are expected in the function syntax, this is guaranteed to never
// /// fail or panic, compared to preparing one with `AccessTokenFlow`.
// ///
// /// But this is not as versatile and extensible, so it should be used with care.  The fact that it
// /// only takes references is a conscious choice to maintain forwards portability while encouraging
// /// the transition to custom `Endpoint` implementations instead.
// pub fn access_token_flow<'a, W>(
//     registrar: &'a dyn Registrar, authorizer: &'a mut dyn Authorizer, issuer: &'a mut dyn Issuer,
// ) -> AccessTokenFlow<AccessToken<'a>, W>
// where
//     W: WebRequest,
//     W::Response: Default,
// {
//     let flow = AccessTokenFlow::prepare(Generic {
//         registrar,
//         authorizer,
//         issuer,
//         solicitor: Vacant,
//         scopes: Vacant,
//         response: Vacant,
//     });

//     match flow {
//         Err(_) => unreachable!(),
//         Ok(flow) => flow,
//     }
// }
