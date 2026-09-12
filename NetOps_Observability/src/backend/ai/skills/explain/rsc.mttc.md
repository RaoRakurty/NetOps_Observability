---
topic: rsc.mttc
question: What is the median correlation time?
keywords: mttc, time to correlate, correlation time, grouping signals
---
MTTC — Median Time To Correlate — is the time taken to group related signals
into one incident, rather than leaving an operator to notice that forty alerts
are one fault. On the NOC Recovery Scorecard it usually tracks closely with
isolation, because in the current engine correlation and isolation are grounded
together: the same evidence that groups the signals is the evidence that names
the owning domain. A large gap between MTTC and MTTI is worth looking at — it
means signals were grouped long before anyone could say whose fault it was.
