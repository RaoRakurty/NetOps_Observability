---
topic: quarantine.why-held
question: Why is an event quarantined?
keywords: quarantine, unattributable event, registry miss, sealed envelope
---
When a device-lane event's sender is not in the device inventory, the router
cannot say which tenant owns it. Rather than guess, it seals the whole event
inside a metadata envelope and parks it here. Only the syslog, trap and flow
lanes have this stage — those are the lanes whose tenant comes from a registry
lookup. This page shows metadata only: the sealed event itself is never served
to it.
