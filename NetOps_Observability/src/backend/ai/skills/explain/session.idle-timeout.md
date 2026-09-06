---
topic: session.idle-timeout
question: What does the idle timeout do?
keywords: idle timeout, sign out after inactivity, session lifetime, maximum lifetime
---
A session with no activity for this many minutes is ended, checked at the
token-refresh boundary rather than by a clock in the browser. It is set per
scope, so the Provider, an organization and a tenant can each choose their
own. A fixed maximum session lifetime applies on top of it as a standard
default: a session that stays busy still ends when that maximum is reached.
Zero turns the idle check off and leaves only the maximum lifetime.
