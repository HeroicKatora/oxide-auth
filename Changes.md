# v0.4.0-preview.1

Ergonomics & Feature rewrite

Replaces the frontend mechanism with a trait based system:
 - Better configurability of underlying primitives
 - Trait introduces central, dedicated error handling
 - Expands the possible types for request and response representation

These interfaces were improved:
 - Names follow existing conventions more closely, such as http status codes
 - Competing usages of 'authorization' has been replaced
 - All requests, functions and flows are now named by their result:
       AuthorizationFlow, AccessTokenFlow, ResourceFlow
 - Actix frontend now supports basic async operations
 - Ransformation wrappers for requests, e.g. MapErr to change error type
 - Error types now have a stricter usage explanation

Breaking changes:
 - Everywhere. Read the migration notes for some help (or open an issue).
 - Sorry. This was necessary to support an asynchronous server library.

Fixed the following bugs:
 - Errors in primitives leading to improper responses
 - Misusage of error types within the library

# v0.4.0-preview.0

Ergonomics & Feature release

Introduces the following features:
 - A frontend for `actix`!
 - Additional traits allow using the backend without having to directly rely
   on primitives.  This is expected to provide enable additional choices for
   frontends in the future.

These interfaces were improved:
 - The documentation now clearly mentions the biggest use cases in the top-level
   documentation.  Documentation now refers to actix as a focus instead or iron.
 - Reduced compilation dependencies for some combination of features.
 - Additional examples in the documentation

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

# v0.3 (2018-Feb-23)

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


# v0.2

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
