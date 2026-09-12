---
topic: sso.elevation-provider
question: What is an elevation provider?
keywords: elevation provider, elevation, standing provider, jit access, step-up, elevated access
---
A second identity provider that grants access instead of creating it. A
standing provider signs people in: it provisions the account, sets its tenant
and carries its everyday role. An elevation provider does none of that.
Signing in through one adds a time-bound grant to an account that already
exists, and the grant expires on its own. It cannot create an account, move a
tenant or change a standing role.

Some actions require it — opening a vendor case, a device shell, granting a
role. Those refuse a standing session and name the provider to use.

Set the maximum duration, and optionally the claims for the duration, the
change ticket and the device it covers. A claim only shortens.
