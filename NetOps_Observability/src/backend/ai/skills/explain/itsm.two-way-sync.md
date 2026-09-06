---
topic: itsm.two-way-sync
question: What does bidirectional sync change?
keywords: bidirectional sync, outbound, inbound state changes, webhook
---
Outbound is the default: the platform promotes its own incidents into the
external system and updates them there. Bidirectional adds the other direction
— acknowledgement, resolution and reassignment done in the external system are
applied back onto the incident here, delivered through a registered, HMAC-
signed webhook. Inbound needs a signing secret; without one the platform will
not accept a callback at all.
