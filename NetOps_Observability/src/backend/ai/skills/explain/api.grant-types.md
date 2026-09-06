---
topic: api.grant-types
question: What are grant types?
keywords: grant types, oauth flows, client credentials, authorization code
---
The OAuth 2.0 flows this credential is allowed to use. `client_credentials` is
the usual machine-to-machine flow: the client presents its id and secret and
receives a token. `authorization_code` is for a client acting on behalf of a
person, and `refresh_token` lets a client renew without re-authenticating.
Selecting a flow the client does not use costs nothing but grants nothing
either — pick only what you need.
