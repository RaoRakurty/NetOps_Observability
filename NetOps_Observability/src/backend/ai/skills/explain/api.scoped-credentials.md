---
topic: api.scoped-credentials
question: What can an API key do?
keywords: api key scopes, machine credential, key never exceeds its scopes
---
A key carries an explicit list of scopes, and the role it acts under is
derived from them. It can never do more than those scopes allow, and it can
never exceed the authority of whoever minted it — the server refuses a scope
that would give the key more than the caller holds. Keys are tenant-bound: a
key minted inside a tenant only ever sees that tenant's data. Revoking a key
stops it at the next request.
