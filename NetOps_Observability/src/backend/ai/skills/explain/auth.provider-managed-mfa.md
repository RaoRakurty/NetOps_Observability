---
topic: auth.provider-managed-mfa
question: Why can I not turn two-factor on for this account?
keywords: managed by your identity provider, federated account, sso mfa, no controls, second factor
---
This account signs in through your identity provider — SSO, LDAP or TACACS+ —
not with a password the platform stores. Its second factor therefore lives at
the provider too, and is turned on and off where you sign in. Any button on
this card would be a lie: the platform cannot add a factor the provider did not
perform, and cannot remove one it does not own. Ask whoever administers that
provider. A platform admin can still require a second factor at the door under
Administration → Authentication, which refuses sign-ins the provider did not
verify with one.
