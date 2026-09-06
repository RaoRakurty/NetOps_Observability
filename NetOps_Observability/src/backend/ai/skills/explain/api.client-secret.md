---
topic: api.client-secret
question: How do I use the client secret?
keywords: client secret, bearer token, x-api-key header, present the secret
---
Present it as `Authorization: Bearer <secret>` or in the `X-API-Key` header.
It is shown once, at creation, and never again — the platform stores only a
hash of it. The key resolves to the same tenant and the same permission grid
as its scopes, never more. If it is lost, revoke the key and mint another;
there is no way to recover it.
