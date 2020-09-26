# oxide-auth

A OAuth2 server library, for use in combination with common web servers,
featuring a set of configurable and pluggable backends.

## About

`oxide-auth` aims at providing a comprehensive and extensible interface to
managing OAuth2 tokens on a server. The core package is agnostic of the used
front-end web server and adaptors for the actix, rocket, iron and rouille
crates are provided in extension crates. Through an interface designed with
traits, the frontend is as easily pluggable as the backend. You can provide
your own request, response and error types as well as choose any custom method
of authenticating clients and users by implement the appropriate traits.

## Integration into Front-Ends

Some popular server libraries have ready-made integration. These still require
some dependency on the base crate but generally wrap the interface into a user
that is considered more idiomatic for their library. Besides the implementation
of `oxide-auth` traits for the request type, specific error and response traits
are also implemented.

| What | Crate | Notes | Docs |
|-|-|-|-|
| `actix` | `oxide-auth-actix` | - | [![actix docs](https://docs.rs/oxide-auth-actix/badge.svg)](https://docs.rs/oxide-auth-actix) |
| `async` wrappers | `oxide-auth-async` | - | [![actix docs](https://docs.rs/oxide-auth-actix/badge.svg)](https://docs.rs/oxide-auth-actix) |
| `redis` | `oxide-auth-db` | - | [![redis docs](https://docs.rs/oxide-auth-db/badge.svg)](https://docs.rs/oxide-auth-db) |
| `rocket` | `oxide-auth-rocket` | nightly | [![rocket docs](https://docs.rs/oxide-auth-rocket/badge.svg)](https://docs.rs/oxide-auth-rocket) |
| `rouille` | `oxide-auth-rouille` | - | [![rouille docs](https://docs.rs/oxide-auth-rouille/badge.svg)](https://docs.rs/oxide-auth-rouille) |
| `iron` | `oxide-auth-iron` | - | [![iron docs](https://docs.rs/oxide-auth-iron/badge.svg)](https://docs.rs/oxide-auth-iron) |


## Additional

Licensed under either of
 * MIT license ([LICENSE-MIT] or http://opensource.org/licenses/MIT)
 * Apache License, Version 2.0 ([LICENSE-APACHE] or http://www.apache.org/licenses/LICENSE-2.0)
at your option.

The license applies to all parts of the source code, its documentation and
supplementary files unless otherwise indicated. It does NOT apply to the
replicated full-text copies of referenced RFCs which were included for the sake
of completion. These are distributed as permitted by [IETF Trust License
4–Section 3.c.i][IETF4].
