Details breaking changes and migration possibilities. Report missing
information with an issue. For guides on larger migrations you may also request
more detailed information.

## v0.4.0-preview.1 [WIP]

Currently trying to streamline traits and method by making them less specialized
and reusable or hiding complexity behind a more succinct interface. Part of this
is cleaning up interfaces that were misguided by envisioning them with a too
heavy focus on optimization but sacrificing usability in the process. And as it
later turned out, this choice also introduced complicated inter-module
dependencies that reduced the overall available design space. Sacrificing
functionality for a small performance boost is not an acceptable tradeoff.

This migration notice denotes WIP or planned changes on the git version and will
be merged into a single log when a release is made. WIP changes may appear in
`preview.2` or later and are intended to provide advance notice of expected
interface changes.

-----

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

[WIP] The `code_grant::frontend` flow design has been revamped into a unified
trait. This replaces the explicit `…Flow` constructors while allowing greater
customization of errors, especially allowing the frontend to react in a custom
manner to `primitive` errors or augment errors of its own type. This should open
the path to more flexible `future` based implementations.

-----

[WIP] QueryParamter is now a private struct with several `impl From<_>` as
substitutes for the previous enum variants. This should make frontend
implementation more straightforward by simply invoking `.into()` while allowing
introduction of additional representations in a non-breaking change (variants of
public enums are strictly speaking breaking changes while new impls of crate
types are not).

-----

## v0.4.0-preview0

Actix is the only fully supported framework for the moment as development begins
on trying to support `async` based frameworks. This release is highly
experimental and some breaking changes may go unnoticed due to fully switching
the set of frontends. Please understand and open a bug report if you have any
migration issues.
