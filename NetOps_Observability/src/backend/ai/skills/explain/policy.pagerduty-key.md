---
topic: policy.pagerduty-key
question: What is this routing key used for?
keywords: pagerduty routing key, events api v2, tenant own key
---
This tenant's own Events API v2 integration key. It is used only by the
PagerDuty incident policies below — nothing else in the platform pages through
it, and raw alerts never reach it. It is write-only: type a new key to replace
the stored one, or leave it blank to keep what is there.
