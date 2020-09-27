# oxide-auth

A OAuth2 server library, for use in combination with common web servers,
featuring a set of configurable and pluggable backends.

## About

`oxide-auth` aims at providing a comprehensive and extensible interface to
managing OAuth2 tokens on a server. The core package is agnostic of the used
front-end web server and adaptors for the actix, rocket, iron and rouille
crates are provided in extension crates. Through an interface designed with
traits, the frontend is as easily pluggable as the backend.

## Example

> `$ cargo run example-actix`

In the example folder you can find an [interactive example]. This configures
a server, registers a public client and initializes a resource requiring an
authorization token. A client is also activated which can be used to access the
resource. The example assumes the user to be the validated resource owner, who
can deny or allow the request by the client.

## Integration

Some popular server libraries have ready-made integration. These still require
some dependency on the base crate but generally wrap the interface into a user
that is considered more idiomatic for their library. Besides the implementation
of `oxide-auth` traits for the request type, specific error and response traits
are also implemented.

| What | Crate | Notes | Docs |
|-|-|-|-|
| `actix` | `oxide-auth-actix` | - | [![actix docs](https://docs.rs/oxide-auth-actix/badge.svg)](https://docs.rs/oxide-auth-actix) |
| `async` wrappers | `oxide-auth-async` | - | [![async docs](https://docs.rs/oxide-auth-async/badge.svg)](https://docs.rs/oxide-auth-async) |
| `redis` | `oxide-auth-db` | - | [![redis docs](https://docs.rs/oxide-auth-db/badge.svg)](https://docs.rs/oxide-auth-db) |
| `rocket` | `oxide-auth-rocket` | nightly | [![rocket docs](https://docs.rs/oxide-auth-rocket/badge.svg)](https://docs.rs/oxide-auth-rocket) |
| `rouille` | `oxide-auth-rouille` | - | [![rouille docs](https://docs.rs/oxide-auth-rouille/badge.svg)](https://docs.rs/oxide-auth-rouille) |
| `iron` | `oxide-auth-iron` | - | [![iron docs](https://docs.rs/oxide-auth-iron/badge.svg)](https://docs.rs/oxide-auth-iron) |

## Additional

[![Crates.io Status](https://img.shields.io/crates/v/oxide-auth.svg)](https://crates.io/crates/oxide-auth)
[![Docs.rs Status](https://docs.rs/oxide-auth/badge.svg)](https://docs.rs/oxide-auth/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/HeroicKatora/oxide-auth/dev-v0.4.0/docs/LICENSE-MIT)
[![License](https://img.shields.io/badge/license-Apache-blue.svg)](https://raw.githubusercontent.com/HeroicKatora/oxide-auth/dev-v0.4.0/docs/LICENSE-APACHE)
[![CI Status](https://api.cirrus-ci.com/github/HeroicKatora/oxide-auth.svg)](https://cirrus-ci.com/github/HeroicKatora/oxide-auth)

A more or less comprehensive list of changes is contained in the
[changelog][CHANGES]. Sometimes less as larger releases and reworks profit from
a rough overview of the changes more than a cumulative list of detailed
features.

For some hints on upgrading from older versions see the [migration
notes][MIGRATION].

More information about [contributing][CONTRIBUTING]. Please respect that I
maintain this on my own currently and have limited time. I appreciate
suggestions but sometimes the associate workload can seem daunting. That means
that simplifications to the workflow are also *highly* appreciated.

Licensed under either of
 * MIT license ([LICENSE-MIT] or http://opensource.org/licenses/MIT)
 * Apache License, Version 2.0 ([LICENSE-APACHE] or http://www.apache.org/licenses/LICENSE-2.0)
at your option.

The license applies to all parts of the source code, its documentation and
supplementary files unless otherwise indicated. It does NOT apply to the
replicated full-text copies of referenced RFCs which were included for the sake
of completion. These are distributed as permitted by [IETF Trust License
4–Section 3.c.i][IETF4].

[actix]: https://crates.io/crates/actix-web
[iron]: https://crates.io/crates/iron
[rocket]: https://crates.io/crates/rocket
[rouille]: https://crates.io/crates/rouille
[interactive example]: oxide-auth-actix/examples/actix-example
[CHANGES]: Changes.md
[MIGRATION]: Migration.md
[CONTRIBUTING]: docs/CONTRIBUTING.md
[LICENSE-MIT]: docs/LICENSE-MIT
[LICENSE-APACHE]: docs/LICENSE-APACHE
[IETF4]: https://trustee.ietf.org/license-info/IETF-TLP-4.htm
