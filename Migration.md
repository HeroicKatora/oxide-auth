Details breaking changes and migration possibilities. Report missing
information with an issue. For guides on larger migrations you may also request
more detailed information.

## v0.4.0-preview.1 [WIP]

A HUGE refactor of the backend part of the library. For the `actix` part, see the
relevant section.

Currently trying to streamline traits and method by making them less specialized
and reusable or hiding complexity behind a more succinct interface. Part of this
is cleaning up interfaces that were misguided by envisioning them with a too
heavy focus on optimization but sacrificing usability in the process. And as it
later turned out, this choice also introduced complicated inter-module
dependencies that reduced the overall available design space. Sacrificing
functionality for a small performance boost is not an acceptable tradeoff.

[WIP]
Documentation changes all around with an improved structure:
* `code_grant` contains core algorithms.
* `code_grant::endpoint` contains the generic `Endpoint`, `WebRequest`,
  `WebResponse` and `xFlow` traits to generalize frontend implementations. Also
  note the wording now refers to these features as 'Endpoint' related while
  'frontend' is used for http-library specific components. When other OAuth
  methods are supported, this may instead move to its own top-level module.
* `frontends::simple` contains reusable abstractions for endpoints. That is, an
  an owning request and response struct. Similar abstractions previously existed
  for test purposes only.
* [WIP] Extensions are now implemented in such a way as to be used standalone.
  While the `simple` frontend offers some trait based `System` to make use of
  multiple independent extensions at the same time, this is no longer required
  for other frontends.

[WIP]
The following names have changed for consistency:
* Types of request-response mechanisms are now prefixed with the resource that
  the requesting party (i.e. the client) tries to access. In particular:
* `CodeRequest`, `CodeFlow`, … to `AuthorizationRequest`, `AuthorizationFlow`
* `GuardFlow`, … to `ResourceFlow`
* The `OwnerAuthorizer` has been named to `OwnerSolicitor` to emphasize its
  role in conjunction with the resource owner and avoid confusing with directly
  'authorization' related types.

This migration notice denotes WIP or planned changes on the git version and will
be merged into a single log when a release is made. WIP changes are intended to
provide advance notice of expected interface changes and may appear only in
`preview.2` or later. In that case, they will be moved to the according
migration note.

### Actix frontend

The standardization of a simple, reusable `Endpoint` offers exiting new
possibilites. Foremost, a simple newtype wrapper around this and other
primitives imbues them with `Actor` powers and messaging [WIP]. Requests and
responses are now more composable so the former now has a simpler representation
and the necessity of tacking on owner owner consent information has been moved
to messages entirely [WIP]. Messages for other primitive types have been added,
so that even a `Registrar` or an `Issuer` can be run as their own actors. That
might be very useful to attach them to a database backend.

The initial construction of a `OAuthRequest` is now the result of an
`OAuthFuture` that consumes the http request. This has simply been shifted from
the actix message constructors. Since `OAuthRequest` now also implements
`WebRequest` in a simple manner, many implementors will likely want to use a
newtype style to further customize error types and response representations.
Keep in mind that for a request to be useable as a message to an endpoint actor,
the error types of the two have to agree. This restriction may be lifted in
later versions.

[WIP]
This specific frontend also offers another `Endpoint` variant that is
constructed using futures. This special implementation buffers partial results
from primitives to retry a flow when polling from one of its futures fails.

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

[WIP] Endpoints and responses can also rely on call restrictions to these new
methods. For example, all flows will at most call one `body_` variants of 
`WebResponse` and `Endpoint::response` will be called at most once per flow
execution. This could prove useful to high-performance implementations that
want to recycle response instances and avoiding allocation. It should be 
possible to use a `&mut _` as a `WebResponse` in an endpoint implementation.

[WIP] These restricted call properties have tests.

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

[WIP]
Extension have been redesigned. Instead of the backend iterating over a set of
extensions provided by the endpoint, the endpoint implementation now has full
control over the input and output extension data in a single function call. The
traits `AuthorizationExtension` etc. have been moved to the new
`frontends::simple`.

Rationale: This is to allow groups of extensions working closely together, such
as possibly for OpenID in the future. It also solves a few efficieny and design
issues by leaving the representation more open to library users/frontends.

----

[WIP]
Error variant namings and usages have been clarified. Specifically, such names
should now correspond more closely to HTTP status codes where applicable.

## v0.4.0-preview0

Actix is the only fully supported framework for the moment as development begins
on trying to support `async` based frameworks. This release is highly
experimental and some breaking changes may go unnoticed due to fully switching
the set of frontends. Please understand and open a bug report if you have any
migration issues.
