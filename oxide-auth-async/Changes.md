# v0.1.1 (2023-Sep-23)

Feature release:
- Adds `client_credentials` module, implemented following the `oxide-auth` base implementation.
- Adds the `ClientCredentialFlow` for asynchronous endpoint implementations.
- Implements the asynchronous traits for `oxide_auth`'s basic endpoint wrapper types:
  `AddonList`, `Extended` from `oxide_auth::frontends::simple`.

Maintenance changes:
- Bumps `oxide_auth` required version to `0.5.4`.
