---
topic: threats.none-matched
question: No detections fired — is the estate clean?
keywords: no detection fired, no rule matched, nothing detected
---
No rule matched what was ingested in this window. That is not the same as a
clean estate: a rule that is disabled, a log source that is not arriving, and
an estate with nothing happening all produce an empty list. Check Detection
Rules for what is enabled, Data Sources for whether device logs are arriving,
and Network Behavior for flow-derived activity that no log rule would see.
