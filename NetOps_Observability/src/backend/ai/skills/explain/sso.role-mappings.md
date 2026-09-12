---
topic: sso.role-mappings
question: Where are external SSO role mappings configured?
keywords: sso role mappings, idp group to role, external roles
---
They live with the identity provider that produces them, under Administration
→ Authentication: each connected provider carries its own list of group-or-
claim values and the platform role each one grants. That is why this tab
points there instead of holding a second copy — one mapping list per provider
is the only way the "first match wins" ordering can mean anything.
