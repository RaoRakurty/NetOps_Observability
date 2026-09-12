---
topic: admin.rca-ticketing
question: When does a root cause open a ticket?
keywords: auto ticketing, incident policy, one ticket per root cause
---
A policy decides. It looks at the RCA verdict, the peak severity, whether
anything customer-facing is affected and how long the fault has persisted,
then either opens one ticket for that root cause or holds it. The unit is the
root cause, never the raw alert: a hundred correlated alerts still produce one
ticket, updated in place and closed when the fault clears.
