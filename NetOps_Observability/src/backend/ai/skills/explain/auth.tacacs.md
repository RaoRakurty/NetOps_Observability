---
topic: auth.tacacs
question: How does TACACS+ sign-in work?
keywords: tacacs, aaa server, pap, operators, shared secret
---
Operators authenticate against the same AAA server that fronts your routers
and switches, using TACACS+ PAP (RFC 8907). It is the simplest way to give a
NOC one set of credentials for the network and for this platform.
Authenticated users receive the default role and tenant you set here — TACACS+
carries no group information the platform maps. The shared secret is write-
only.
