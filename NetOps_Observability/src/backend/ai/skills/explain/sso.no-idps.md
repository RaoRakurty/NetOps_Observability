---
topic: sso.no-idps
question: What does registering an identity provider do?
keywords: no identity providers, add idp, sign-in button, keycloak broker
---
Registering one puts a named button — "Okta", "Azure AD" — on the sign-in
page, brokered through the platform's Keycloak realm. Until one is registered,
the only way in is a local account or a directly configured directory. Adding
a provider does not change who may sign in: the group-to-role mapping still
decides what a federated user can reach, and no mapping means the default
role.
