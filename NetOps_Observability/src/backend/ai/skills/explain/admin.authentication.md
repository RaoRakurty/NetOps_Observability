---
topic: admin.authentication
question: How do people sign in?
keywords: authentication, sign in methods, sso ldap tacacs, local fallback
---
Four ways, and they can run together. Local accounts always work and are the
fallback. Single Sign-On federates the login to your OIDC identity provider.
LDAP or Active Directory binds straight to your directory. TACACS+
authenticates operators against the same AAA server that fronts your routers
and switches. Pick a tile to configure one; each records its own status, and a
provider that is enabled but incomplete says so.
