---
topic: admin.sessions
question: What is on the Sessions page?
keywords: sessions, live sign-ins, revoke session, idle out
---
Every sign-in session the platform is currently tracking, with the person, the
tenant, the source address and when they were last active. Revoking one signs
that person out immediately — their next request is refused and they must sign
in again. Sessions also end on their own: idle-out uses the scope's Security
Settings, and every session has a fixed maximum lifetime on top of that. A
tenant admin sees only their own tenant's sessions.
