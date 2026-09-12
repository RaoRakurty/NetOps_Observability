---
topic: auth.local
question: What are local accounts?
keywords: local accounts, username and password, pbkdf2, always on fallback
---
Accounts stored by the platform itself. They authenticate with a username and
password hashed with PBKDF2, and the platform issues its own JWT access token
with a rotating, single-use refresh token. They are always available —
including when an external identity provider is unreachable, which is why they
cannot be turned off. Password complexity, lockout and session lifetimes come
from the scope's Security Settings, not from this page.
