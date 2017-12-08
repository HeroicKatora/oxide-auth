oxide-auth
==============
A OAuth2 server library, for use in combination with iron or other frontends, featuring a set of configurable and pluggable backends.

About
--------------
`oxide-auth` aims at providing a comprehensive and extensible interface to managing oauth2 tokens on a server. While the core package is agnostic of the used frontend, an optional iron adaptor is provided with the default configuration. Through an interface designed with traits, the frontend is as easily pluggable as the backend.

Example
-------------
In the [example folder] you can find an [interactive example]. This configures a server, registers a public client and initializes a resource requiring an authorization token. A client is also activated which can be used to access the resource. The example assumes the user to be the validated resource owner, who can deny or allow the request by the client.
