---
topic: token.policy-bounds
question: Why are token lifetimes clamped?
keywords: token policy, access token ttl, refresh token ttl, safe bounds
---
Access and refresh token lifetimes are held inside the bounds RFC 9700 and
NIST 800-63B recommend, and a value outside them is adjusted on save rather
than refused. A short access token limits how long a stolen one is useful; a
bounded refresh token limits how long a session can be resurrected. Refresh
tokens are single-use with reuse detection — presenting one twice revokes the
whole lineage.
