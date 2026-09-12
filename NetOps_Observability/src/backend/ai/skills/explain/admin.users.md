---
topic: admin.users
question: Who are the users here?
keywords: users directory, who can sign in, local accounts, federated users
---
Everyone who can sign in to this scope. Local accounts are created here and
authenticate with a username and password. Federated users — arriving through
SSO, LDAP or TACACS+ — appear once an identity provider is configured under
Authentication; their password lives at the provider, not here. The Auth
column says which of the two an account is. A tenant admin sees only that
tenant's directory; the platform owner can scope the directory to the Provider
realm or to any one tenant.
