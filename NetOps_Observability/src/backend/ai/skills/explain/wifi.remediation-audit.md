---
topic: wifi.remediation-audit
question: What is recorded when a remediation is decided?
keywords: remediation audit, audit event, verification pending, executed record
---
Every transition is an audit event: who proposed it, who approved or rejected
it and with what reason, when it ran and what came back. After an execution the
originating observation is re-measured in a settle window before anything is
called fixed, so the record can read executed and unverified at the same time.
A failed execution keeps the refusal text it was given; it is never re-labelled
as a transient error.
