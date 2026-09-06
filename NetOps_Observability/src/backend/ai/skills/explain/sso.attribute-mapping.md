---
topic: sso.attribute-mapping
question: What do user attribute mappings do?
keywords: attribute mapping, claims, user profile, first login
---
They say which attribute or token claim from the identity provider fills each
field of the platform's own user profile — display name, email, and anything
else the provider asserts. They are applied on first login, when the local
record for that federated user is created. Changing them does not rewrite
profiles that already exist.
