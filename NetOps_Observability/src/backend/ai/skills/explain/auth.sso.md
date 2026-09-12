---
topic: auth.sso
question: What does Single Sign-On do here?
keywords: sso, oidc, authorization code, okta azure ad, broker
---
Sign-in is federated to your OIDC identity provider using the Authorization
Code flow. The platform brokers the login and then issues its own session, so
what your users end up holding is a platform token, not the provider's. Okta,
Azure AD, Google and any standards-compliant provider work. The client secret
is write-only: leave the field blank to keep the one already stored.
