---
topic: topo.read-failed
question: What does it mean when the topology cannot be read?
keywords: topology read failed, topology service did not answer, unknown network shape
---
The topology service did not answer, so the shape of your network is unknown
for this view. This is deliberately not drawn as an empty network: an empty
canvas would say you have no devices, and nothing here supports that. Retry
first — the read is a normal request and can fail transiently. If it keeps
failing, the topology service or its store is the thing to check, not
discovery.
