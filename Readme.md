oxide-auth
==============
A OAuth2 server library, for use in combination with [actix] or other frontends, featuring a set of configurable and pluggable backends.

About
--------------
`oxide-auth` aims at providing a comprehensive and extensible interface to managing oauth2
tokens on a server. While the core package is agnostic of the used frontend, an optional actix and a gotham
adaptor is provided with the default configuration. Through an interface designed with traits,
the frontend is as easily pluggable as the backend.

Example
-------------

> `$ cargo run --example authorization_actix`

In the [example folder] you can find an [interactive example]. This configures a server, registers a public client and initializes a resource requiring an authorization token. A client is also activated which can be used to access the resource. The example assumes the user to be the validated resource owner, who can deny or allow the request by the client.

Additional
----------
[![Crates.io Status](https://img.shields.io/crates/v/oxide-auth.svg)](https://crates.io/crates/oxide-auth)
[![Docs.rs Status](https://docs.rs/oxide-auth/badge.svg)](https://docs.rs/oxide-auth/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/iron/iron/master/LICENSE)

More information about [contributing][CONTRIBUTING].

[actix]: https://crates.io/crates/actix-web
[example folder]: examples/
[interactive example]: examples/authorization_actix.rs
[CONTRIBUTING]: docs/CONTRIBUTING.md
