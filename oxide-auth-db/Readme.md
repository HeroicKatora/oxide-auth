# oxide-auth-db

A DataBase Registrar Implementation for `oxide-auth`.

## About

This cargo by-default provides a Redis Registrar Implementation. Users can add
different Database Implementation in the db_service package.  Then use the
feature set to configure which db you want to use in the `Cargo.toml` file.

```
[features]
default = ["with-redis"]
with-redis = ["r2d2","r2d2_redis"]
```


## Example

Users should have a redis server in their environment and run the commands
below to add a test client to redis.

> `set LocalClient "{\"client_id\":\"LocalClient\",\"redirect_uri\":\"http://localhost:8021/endpoint\",\"additional_redirect_uris\":[],\"default_scope\":\"default-scope\",\"client_secret\":\"$argon2i$v=19$m=4096,t=3,p=1$FAnLM+AwjNhHrKA2aCVxQDmbPHC6jc4xyiX1ioxr66g$7PXkjalEW6ynIrkWDY86zaplnox919Tbd+wlDOmhLDg\"}"`

Then you can run the db-example.

> `$ cargo run db-example`

You may have to wait a second after the html page automatically opened.

## Additional

[![Crates.io Status](https://img.shields.io/crates/v/oxide-auth-db.svg)](https://crates.io/crates/oxide-auth-db)
[![Docs.rs Status](https://docs.rs/oxide-auth-db/badge.svg)](https://docs.rs/oxide-auth-db/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/HeroicKatora/oxide-auth/dev-v0.4.0/docs/LICENSE-MIT)
[![License](https://img.shields.io/badge/license-Apache-blue.svg)](https://raw.githubusercontent.com/HeroicKatora/oxide-auth/dev-v0.4.0/docs/LICENSE-APACHE)
[![CI Status](https://api.cirrus-ci.com/github/HeroicKatora/oxide-auth.svg)](https://cirrus-ci.com/github/HeroicKatora/oxide-auth)

Licensed under either of
 * MIT license ([LICENSE-MIT] or http://opensource.org/licenses/MIT)
 * Apache License, Version 2.0 ([LICENSE-APACHE] or http://www.apache.org/licenses/LICENSE-2.0)
at your option.

[LICENSE-MIT]: docs/LICENSE-MIT
[LICENSE-APACHE]: docs/LICENSE-APACHE
