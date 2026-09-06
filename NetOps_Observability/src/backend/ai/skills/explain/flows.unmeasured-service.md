---
topic: flows.unmeasured-service
question: Why does a service read Not measured?
keywords: not measured, unmeasured service, no selector yet, service catalog selector
---
No selector matches this service yet, so its traffic has never been counted.
Define one and this row becomes a measurement. Until then it reads Not
measured rather than 0 B, it is grouped below the measured services instead of
sorted among them, and it is excluded from the share denominator — a service
nobody has taught us to recognise must never read as an idle one. The Awaiting
a selector tile above counts how many are in this state.
