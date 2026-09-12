---
topic: api.openapi-spec
question: What is the OpenAPI reference?
keywords: openapi, rest reference, openapi.json, postman
---
A live index of the REST surface, generated from the Go handlers themselves
rather than maintained by hand — so it cannot drift from what the server
actually serves. Download `openapi.json` and import it into Postman or any
OpenAPI client to get every endpoint, its parameters and its responses. No
external Swagger bundle is fetched, so it works on an offline install.
