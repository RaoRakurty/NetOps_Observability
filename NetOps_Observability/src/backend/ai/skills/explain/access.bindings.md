---
topic: access.bindings
question: What is an access binding?
keywords: access binding, grant access, role on an organization, revoke
---
A binding is one statement: this person holds this role on this scope.
Granting one gives a person a role on an organization; revoking it takes that
access away immediately. Bindings are additive except for a deny, which wins.
The server enforces no-escalation — an organization admin can only grant
inside their own organization, and can never mint platform authority.
