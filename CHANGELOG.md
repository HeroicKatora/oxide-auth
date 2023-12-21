# Changelog

## `oxide-auth` [UNRELEASED]

### Changed

- Updated `base64` to v0.21
- Updated `rust-argon2` to v2.0.0
- The `Argon2` hasher now uses the parameters recommended by RFC-9106 for memory constrained environments

## `oxide-auth-axum` v0.3.0

### Breaking 

- Updated *oxide-auth-axum* to Axum 0.6 and adapted `OAuthRequest` to `FromRequest` and `OAuthResource` to `FromRequestParts` per https://github.com/tokio-rs/axum/pull/1272
