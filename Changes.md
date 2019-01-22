Versions follow SemVer, of course. Major milestone versions are named in
alphabetic order and will be accompanied by notes in <./Migration.md>.

# v0.4.1 (2019-Jan-22) – Diamond

Feature release

Introduces the following features:
 - Reimplemented frontend for `iron`! Now with 100% more compatible code!
 - Modification functions for `TokenMap` for integration with external issuers.
 - Allow setting the duration of tokens on issuers.

Fixed the following bugs:
 - Fixed a missing trait bound for some older compilers (1.31)
   While those have no guarantee of support, at least one version seem reasonable
 - Links to the `acitx` example in documentation

# v0.4.0 (2019-Jan-20)

Ergonomics & Feature rewrite

Introduces the following features:
 - A frontend for `actix`! Comes with basic 'async' computations.
 - A frontend for `rocket`! Idiomatic integration will be evaluated.
 - Additional traits allow using the backend without having to directly rely
   on primitives.  This is expected to provide enable additional choices for
   frontends in the future.

Breaking changes:
 - Too many to list. Read the migration notes for some help (or open an issue).
   A list containing most of the renamings done is found below. The rest of the
   change notes should give some overview on the extent of this rework.
 - Sorry. This was necessary for basic support of asynchronous server libraries.
   `v0.5.0` will contain even more as `async` becomes a primary feature in Rust.
   These will focus on the `code_grant` and backend parts, so that frontends
   (including `endpoint::Endpoint`) will–hopefully–be largely unaffected.


Replaces the frontend mechanism with a trait based system:
 - Better configurability of underlying primitives
 - Trait `Endpoint` introduces central, dedicated error handling
 - Expands the possible types for request and response representation

These interfaces were improved:
 - Names follow existing conventions more closely, such as http status codes
 - Competing usages of 'extension' has been split into 'Extension' and 'Addon'
 - Competing usages of 'authorization' has been replaced;
   All requests, functions and flows are now named by their result:
       AuthorizationFlow, AccessTokenFlow, ResourceFlow
 - The ResourceFlow now returns the grant that was authorized on success
 - Transformation wrappers for requests, e.g. MapErr to change error type
 - Error types now have a stricter usage explanation
 - Endpoints instantiating responses based on requirements of this library can
   customize the error descriptions and other user-facing output.
 - The documentation now clearly mentions the biggest use cases in the top-level
   documentation.  Documentation now refers to actix as a focus instead of iron.
 - Reduced compilation dependencies for some combination of features.
 - Additional examples in the documentation, examples now named after the 
   frontend they use and generally run a bit smoother.
 - A 'NormalizedParameter' type supporting 'serde' ensures that key-value-pairs 
   passed via query and body have at most one mapping per key.
 - The internal password hashing function `Pbkdf2` has been made public

Fixed the following bugs:
 - Errors in primitives leading to improper responses
 - Misusage of error types within the library
 - Prevent misusage of TokenGenerator (now `TagGrant`) in standard issuers
 - PKCE is now compliant to the base64 encoding laid out in RFC7636
 - Issues with valid authorization requests being rejected

Renamings (`old` -> `new`):
 - `code_grant::frontend` -> `endpoint`
 - `code_grant::frontend::{MultiValueQuery, SingleValueQuery}` -> `_`
   Note: removed in favour of `endpoint::{NormalizedParameter, QueryParameter}`
 - `code_grant::frontend::OwnerAuthorizer` -> `endpoint::OwnerSolicitor`
 - `code_grant::frontend::PendingAuthorization` -> `_`
   Note: no longer exists and is handled through `Endpoint` trait
 - `code_grant::backend::*` -> largely reworked, but logically `code_grant::*`
 - `code_grant::extensions::<trait>` -> `frontends::simple::extensions::*`
   Note: endpoint extensions are grouped in trait `endpoint::Extension`
 - `primitives::authorizer::Storage` -> `primitives::authorizer::AuthMap`
 - `primitives::grant::Extension` -> `primitives::grant::Value`

Thanks and More:
  For all of you that stick with me during the long period of seeming
  inactivity, this has been an exciting year. I've grown a lot in Rust and as a
  developer. The first versions were coined by a bit of naivity on my part and
  this one hopefully feels more mature and idiomatic.

# v0.3.1 (2018-Mar-30)

Feature & Security release

Introduces the following features:
 - A frontend for `gotham`!

These interfaces were improved:
 - The passwords of clients are no longer saved with SHA256 by default. Yeah...
   Instead, a randomly salted combination of password and user identifier is
   supplied to Pbkdf2 with an iteration count of 100'000.  Additionally, the
   interface of the respective registrar offers the possibility to change this
   behaviour at runtime.  The necessary trait is public, which allows arbitrary
   user types.
 - The test suite for registrars was updated to test them more thoroughly.
 - The dependencies for `iron` were update to reflect the latest (and possibly
   last) released version of the framework.

# v0.3 (2018-Feb-23) – Cobalt

Ergonomics & Feature release

Introduces the following features:
 - A frontend for `rouille`!
 - Custom enumeration type for several possible representations of url encoded
   parameters. This should make it possible for nearly every frontend to provide
   a zero-copy implementation of `WebRequest`.
 - Redesign of `WebRequest` and `OwnerAuthorizer` makes it possible to have
   value types as Requests and operate on them instead of `&mut`.

These interfaces were improved:
 - Documentation in `frontends` provides a guide for implementations of custom
   frontends.
 - A cleaner type design for `WebRequest::urlbody` and `WebRequest::query` moves
   the work for ensuring single values in queries further into the library and
   delays enforcing this restriction.
 - The `AuthorizationFlow` is more open as it returns the request initially
   provided when it is done. `OwnerAuthorizer` is no longer mandatory to drive
   this flow but remains a useful tool in some cases where it provides cleaner
   code.


# v0.2 – Basalt

Feature & Bugfix release

Introduced the following features:
 - Extensions for authorization code and access token requests
   A trait based system allows passing a collection of extensions to
   request handlers.  After the basic request checks passed, extensions
   can handle additional parameters of the request.  Based on
   inidivudual logic, they can block the request with an error, attach
   additional information or simply pass it on.  Any attached
   information become available to the same extension in subsequent
   requests with the employed grant.
 - Assertion grants will error when encountering private extensions as
   they currently can not protect/encrypt the data.
 - Each primitive now has a simple test suite which custom implementation
   can run against to test basic compliance.
 - The pkce extension can be leveraged to protect public clients against
   impersonation (e.g. by other programs on a consumer platform).

Fixed the following bugs:
 - Fixed a mistake in the description of the named comparison `Scope`.
   The respective function (`priviledged_to`) is now also mentioned in
   an example in the documentation of `Scope` itself, to illustrate the
   proper functionality and usage.  The symmetric pair (`allow_access`)
   has been introduced as a named function as well.
