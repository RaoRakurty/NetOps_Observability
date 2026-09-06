---
topic: auth.require-mfa
question: What does requiring multi-factor do?
keywords: require mfa, second factor, acr amr, reject sign in
---
Sign-ins your identity provider did not verify with a second factor are
rejected at the door. The platform reads the assurance the provider asserts —
the `acr` values you list, or the sign-in methods in `amr` when you list none
— and refuses anything that does not carry one. It cannot add a factor the
provider did not perform; it can only refuse to accept a login without one.
