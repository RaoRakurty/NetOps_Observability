---
topic: itsm.inbound-pending
question: Why are inbound webhooks recorded but not applied?
keywords: inbound recorded, not driving incident state, platform enablement
---
The platform accepts and records the callbacks — you can see they arrived and
that their signature verified — but it is not yet applying them to incident
state on this deployment. That is a platform-level enablement, not something a
tenant configures. Until it is on, treat the external system as the place
where an inbound change took effect, and this side as outbound only.
