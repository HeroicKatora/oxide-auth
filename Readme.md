oxide-auth
==============
A OAuth2 server library, for use in combination with [actix] or other frontends, featuring a set of configurable and pluggable backends.

About
--------------
`oxide-auth` aims at providing a comprehensive and extensible interface to
managing oauth2 tokens on a server. While the core package is agnostic of the
used frontend, an optional actix and a rouille adaptor is provided with the
default configuration. Through an interface designed with traits, the frontend
is as easily pluggable as the backend.

Example
-------------

> `$ cargo run --example authorization_actix`

In the [example folder] you can find an [interactive example]. This configures
a server, registers a public client and initializes a resource requiring an
authorization token. A client is also activated which can be used to access the
resource. The example assumes the user to be the validated resource owner, who
can deny or allow the request by the client.

Additional
----------
[![Crates.io Status](https://img.shields.io/crates/v/oxide-auth.svg)](https://crates.io/crates/oxide-auth)
[![Docs.rs Status](https://docs.rs/oxide-auth/badge.svg)](https://docs.rs/oxide-auth/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/HeroicKatora/oxide-auth/dev-v0.4.0/docs/LICENSE)

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

The code is [MIT licensed](docs/LICENSE). The license applies to all parts of
the source code, its documentation and supplementary files unless otherwise
indicated. It does NOT apply to the replicated full-text copies of referenced
RFCs which were included for the sake of completion. These are distributed as
permitted by [IETF Trust License 4–Section 3.c.i][IETF4].

[actix]: https://crates.io/crates/actix-web
[example folder]: examples/
[interactive example]: examples/authorization_actix.rs
[CHANGES]: Changes.md
[MIGRATION]: Migration.md
[CONTRIBUTING]: docs/CONTRIBUTING.md
[IETF4]: https://trustee.ietf.org/license-info/IETF-TLP-4.htm
