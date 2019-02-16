Details breaking changes and migration possibilities. Report missing
information with an issue. For guides on larger migrations you may also request
more detailed information.

This migration notice denotes work-in-progress (WIP) or planned changes (NEXT)
before major releases on git version and will be updated into a single log when
a major release or breaking minor release (before 1.0) is made. Both are
intended to provide advance notice of expected interface changes and may be
shifted back in work log arbitrarily. In that case, they will be moved to the
according migration note.

This document is independent of the [release notes](Changes.md).

# [NEXT] v0.5 – Enstatite

As advised in deprecation warnings, the iterators for public and private
extension data of a grant are now constructed via the `public` and `private`
method respectively and the older `iter_public` and `iter_private` method have
been removed. The `is_private` method of `PublicExtensions` is now obsolete and
has been removed since the return type of `private` is now correct.

The wrongly spelled `ephermal` constructor of the `Assertion` grant generator
has been replaced by `ephemeral`.

The crate has been split into a core (`oxide-auth`) and several sub-crates for
each frontend version

The refresh token in `IssuedToken` is now optional. A new attribute for the
token type of the access token has been added, its enum type has a `Default`
implementation that generates the `Bearer` corresponding variant.

The `Issuer::refresh` method no longer has a default implementation. To
replicate the old behaviour, its body should simply consist of `Err(())`.

## v0.4.5

An empty `refresh` token in the `IssuedToken` will no longer inidicate support
for refreshing to the client. Furthermore, refresh tokens need to be
explicitely enabled for `TokenSigner` as there is no good way to revoke them
and are mostly intended for usage in custom signers.

## v0.4.1

The iron frontend has been reworked greatly. It no longer wraps endpoint
related types into custom structs. Users who previously used these features and
want to transition quickly may replace `IronGranter` with the `Generic` struct
and the its flow creation methods with methods of that struct of with functions
found in `frontends::simple::endpoint::*`. A more complete transition for
larger code bases would be implementing `endpoint::Endpoint` yourself. 

Note that `MethodAuthorizer` got replaced by `frontends::simple::FnSolicitor`
and the `IronAuthorizer` has been fully removed. `SimpleAuthorization` was
superseeded by `endpoint::OwnerAuthorization`.

Support for a Bearer token authorizing Middleware implementation has not yet
been implemented. Also, see the notes on `QueryParamter` and module reordering
below in the general migration notes for `v0.4.0`.

# v0.4.0 – Diamond

Below is a reverse chronological list of recommended migration notes. These
have been collected while improving incrementally in preview versions. Read
this list either by searching for required functionality from the top or
tracing the outdated types from the bottom.

Bearer authorization provided by `code_grant::resource` and
`endpoint::ResourceFlow` now returns the extracted `Grant` associated with an
authorized request.  Therefore, additional logic based is safely enabled in the
successful case.

`code_grant::endpoint` has been moved to a top-level module `endpoint`. This
should hint to the fact that the code grant authorization will maybe not be the
only supported method.

Extensions will be implemented in such a way as to be used standalone.
While the `simple` frontend offers some trait based `AddonList` to make use of
multiple independent extensions at the same time, this is no longer required
for other frontends. The data portion of a `GrantExtension` has been renamed to
the more unique `Value`, and the `simple` extension module extends on this
trait to offer `AccessTokenAddon` and `AuthorizationAddon`, simple traits to
implement only a portion of a fullblown system of extension at a time.

Serde support for `NormalizedParameter` so that there is less confusion about
how to construct them and the potential pitfalls of dropping duplicate
keys-value pairs. Strongly assert their non-existence with the respective,
dedicated error code. The frontends duly use this to make good examples.

The `code_grant::endpoint::ResponseKind` enum has been encapsulated in a
private struct (`code_grant::endpoint::Template`) with dedicated methods to
retrieve status code and optional modification objects. With this change,
additional information and customization can be added to the response kind
without breaking the interface.

Primitives have been renamed:
* `authorizer::Storage` to `authorizer::AuthMap`. This is more in line with
  other primitives backed by an in-memory (hash-)map.
* `generator::TokenGenerator` to `generator::TagGrant`. Additional emphasis on
  the fact that the generated tokens should be collision resistant for
  different grants but need not be deterministic (acts similar to a
  non-verifiable signature scheme). Also has better interop with
  `generator::Assertion` by providing a variant of `TaggedAssertion` that
  has `Send + Sync + 'static` and provides an impl of `TagGrant`.

Generally rebuilt `generator::TagGrant`–previously `generator::TokenGenerator`:
* `fn generate(&self, ..)` to `fn generate(&mut self, u64, &Grant)`. But for
  the standard implementations–which do not have any internal mutable state–the
  impl is also provided for `&_`, `Rc<_>` and `Arc<_>`.
* The generics on `AuthMap` and `TokenMap` now default to `Box<TagGrant + Send
  + Sync + 'static>`.  This is sufficient for all `TagGrant` implementations
  provided here.
* `TaggedAssertion` now implements this trait differently. Since the signature
  was deterministic, this has silently broken the security of `TokenMap` by
  issuing the same access and refresh tokens. Since refresh was not provided,
  that did not matter :) The new `counter` that has to be kept by such
  authorizers/issuers makes this interaction secure even for repeating grants.

---------

**v0.4.0-preview.1**

---------

A HUGE refactor of the backend part of the library. For the `actix` part, see the
relevant section.

Currently trying to streamline traits and method by making them less specialized
and reusable or hiding complexity behind a more succinct interface. Part of this
is cleaning up interfaces that were misguided by envisioning them with a too
heavy focus on optimization but sacrificing usability in the process. And as it
later turned out, this choice also introduced complicated inter-module
dependencies that reduced the overall available design space. Sacrificing
functionality for a small performance boost is not an acceptable tradeoff.

Documentation changes all around with an improved structure:
* `code_grant` contains core algorithms.
* `code_grant::endpoint` contains the generic `Endpoint`, `WebRequest`,
  `WebResponse` and `xFlow` traits and structs to generalize frontend
  implementations. Also note the wording now refers to these features as
  'Endpoint' related while 'frontend' is used for http-library specific
  components. When other OAuth methods are supported, this may instead move to
  its own top-level module.
* `frontends::simple` contains reusable abstractions for endpoints. That is, an
  an owning request and response struct. Similar abstractions previously existed
  for test purposes only.

The following names have changed for consistency:
* Types of request-response mechanisms are now prefixed with the resource that
  the requesting party (i.e. the client) tries to access. In particular:
* `CodeRequest`, `CodeFlow`, … to `AuthorizationRequest`, `AuthorizationFlow`
* `GuardFlow`, … to `ResourceFlow`
* The `OwnerAuthorizer` has been named to `OwnerSolicitor` to emphasize its
  role in conjunction with the resource owner and avoid confusing with directly
  'authorization' related types.

### Actix frontend

The standardization of a simple, reusable `Endpoint` offers exiting new
possibilites. Foremost, a simple newtype wrapper around this and other
primitives imbues them with `Actor` powers and messaging. Requests and
responses are now more composable so the former now has a simpler
representation and the necessity of tacking on owner owner consent information
has been moved to messages entirely. Messages for other primitive types have
been added, so that even a `Registrar` or an `Issuer` can be run as their own
actors. That might be very useful to attach them to a database backend.

The initial construction of a `OAuthRequest` is now the result of an
`OAuthFuture` that consumes the http request. This has simply been shifted from
the actix message constructors. Since `OAuthRequest` now also implements
`WebRequest` in a simple manner, many implementors will likely want to use a
newtype style to further customize error types and response representations.
Keep in mind that for a request to be useable as a message to an endpoint
actor, the error types of the two have to agree. This restriction may be lifted
in later versions.

Basic asynchronous handling of requests is provided with three top-level
methods that return a boxed future of appropriate type. This leaves the
internal representation open to future changes. The interface is currently more
restrictive than necessary to keep the interface more stable.  This special
implementation buffers partial results from primitives to retry a flow when
polling from one of its futures fails.

### More or less comprehensive change list

`Registrar` now requires the result of `bound_redirect` to have a lifetime
independent of `self`. Instead of requiring a long-living reference to an
internal `EncodedClient`, scope resolution has been moved to a separate method.

Rationale: This method required taking a borrow on whatever provided the
registrar due to its entangled lifetimes. Since the return value was needed
later in the authorization process the non-local borrow hindered simultaneous
usage of other mutable members, even if those were local.

At the same time, this change implies that the underlying storage of a
`Registrar` is no longer restricted to `EncodedClient` and can use arbitrary
data structures.

-----

`Registrar` also no longer requires returning a `RegisteredClient` in its
interface. The `client` method has been replaced with 

> `fn check(&self, client_id: &str, passphrase: Option<&[u8]>` 

which should perform the equivalent of 

```
self.client(client_id).ok_or(Unspecified)?.check_authentication(passphrase)
```

while leaving the internal representation undetermined.

Rationale: Tries to avoid having any references into the inner representation
that do not refer to types which can be cloned into an owned representation.
Such types make it harder than necessary to create an interface with
messages/actors/async. Since the `client` method had no other purpose than the
equivalent usage shown above, this choice should be fairly uncontroversial.

-----

`Authorizer` and `Issuer` have gained a way to signal internal consistency
failure in their token lookup methods. The return type changed from
`Option<Grant>` to `Result<Option<Grant>, ()>`. If a custom implementation
previously did not rely on returning an error response, just wrap it in an
`Ok`.

-----

Construction of `WebResponse` instances (e.g. by `redirect_error`) has been 
removed from `WebResponse`. Instead, a new method `response` has been added to
`Endpoint` that may inspect the request and kind of response required. All 
modifier functions such as `client_error`, `json`, etc. have also been reworked
to instead work on mutable references to the `WebResponse`.

Rationale: It is the endpoint that contains the implementation specific logic.
Since the error can only be enriched with additional information or references
to other pages before it is converted to a `WebResponse`, this logic is not
universal for implementations for `WebResponse` but rather needs customization
from the endpoint.

Endpoints and responses can also rely on call restrictions to these new
methods. For example, all flows will at most call one `body_` variants of
`WebResponse` and `Endpoint::response` will be called at most once per flow
execution. This could prove useful to high-performance implementations that
want to recycle response instances and avoiding allocation. It should be
possible to use a `&mut _` as a `WebResponse` in an endpoint implementation.

-----

The previous `OwnerAuthorizer` and `OwnerAuthorization` have been renamed to
`OwnerSolicitor` and `OwnerConsent` to avoid confusion arising from the use of
'authorization'. Additionally, it has been integrated in the endpoint next to
other primitives, no frontend actually supported very different usage anyways.

-----

The `code_grant::frontend` flow design has been revamped into a unified trait.
This replaces the explicit `…Flow` constructors while allowing greater
customization of errors, especially allowing the frontend to react in a custom
manner to `primitive` errors or augment errors of its own type. This should
open the path to more flexible `future` based implementations.

-----

QueryParamter is now a private struct with several `impl From<_>` as substitutes
for the previous enum variants. This should make frontend implementation more
straightforward by simply invoking `.into()` while allowing introduction of
additional representations in a non-breaking change (variants of public enums
are strictly speaking breaking changes while new impls of crate types are not).
As an added bonus, this change enabled many more zero-copy representations for
query parameters.

Rationale: The previous version was not ergonomic to use while tempting users
into relying on underlying libraries to correct not deduplicate key-value
pairs. Note that for example the following is incorrect:

```
//! serde_urlencoded::from_str::<HashMap<String, String>>(query)?.normalize();
```

Instead, deserialize to `NormalizedParameter`

```
serde_urlencoded::from_str::<Vec<(String, String)>>(query)?.into_iter().collect();
```

-----

The possibility to create a `TokenSigner` instance based on a password has been
removed. The use of this was discouraged all along but this removes another
possible security pit fall. Note that you may want to migrate to a self-created
`ring::hmac::SigningKey` instance, using a randomly generated salt and a
self-chosen, secure password based key derivation function to derive the key
bytes. Alternatively, you can now create a `TokenSigner` that uses an ephemeral
key, i.e. the key will change for each program invocation, invalidating all
issued tokens of other program runs.

Rationale: Password based, low-entropy keys do not provide adequate security.
While the interface offered the ability to provide a high-entropy salt to
create a secure signing key, it was easy not to do so (and done in the examples
against the recommendation of the documentation). The scenario for the
examples, and by extension maybe the scenario of users, did not rely on
persistent keys. The new interface should offer high security both for a
configuration-free setup and a production environment. Relying on the standard
constructors for `SigningKey` is intended to urge users to correctly use
high-entropy inputs such as the default rng of standard password hashing
algorithms.

----

A new simple frontend (`frontends::simple`) has been introduced to serve as a
common denominator for other implementations. Its data types are built for
simplicity and used in tests, replacing the previous private test module
implementations.

----

`Endpoint::Error` no longer requires traits bounds of `From<OAuthError>` and
`From<Request::Error>`. Instead, a dedicated callback method taking `&mut self`
of the endpoint does that conversion.

Rationale: The trait bounds puts some restrictions on implementing endpoints
with error types that are not defined in the current trait. Additionally, it
made it impossible to generalize over the underlying request type, as there is
no way to implemention `impl<T> From<T> for ErrorType`, of course.

----

Extension have been redesigned. Instead of the backend iterating over a set of
extensions provided by the endpoint, the endpoint implementation now has full
control over the input and output extension data in a single function call. The
traits `AuthorizationExtension` etc. have been moved to the new
`frontends::simple`. They can NOT be used in the async portions of the actix
frontend.

Rationale: This is to allow groups of extensions working closely together, such
as possibly for OpenID in the future. It also solves a few efficieny and design
issues by leaving the representation more open to library users/frontends.
Since extension do not provide guarantees on idempotency, they can not be
simply retried. Therefore, the asynchronous interface of actix can not
currently make use of them. Sorry.

----

Error variant namings and usages have been clarified. Specifically, such names
should now correspond more closely to HTTP status codes where applicable.

----

** v0.4.0-preview0 **

----

Actix is the only fully supported framework for the moment as development begins
on trying to support `async` based frameworks. This release is highly
experimental and some breaking changes may go unnoticed due to fully switching
the set of frontends. Please understand and open a bug report if you have any
migration issues.
