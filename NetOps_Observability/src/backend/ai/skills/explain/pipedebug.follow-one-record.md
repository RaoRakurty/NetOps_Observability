---
topic: pipedebug.follow-one-record
question: What does following one record do?
keywords: pipeline debugger, marked record, ingress, never to a device
---
It puts one marked record into the stack's own ingress and reports every hop
it crossed — parser, router, bus, sink — with the reason each hop gave.
Nothing is ever sent to a device: the record originates here. For gNMI, where
an update can only start at the device, it follows real traffic for the device
and window you choose instead of injecting anything.
