---
topic: wan.policy
question: What does the measurement policy control?
keywords: measurement policy, wan device pattern, derived registry, policy saved
---
The policy is the only thing stored on this page. It decides which devices
count as WAN devices, whether interfaces connected to them are measured too,
what the fallback anchors are, and which ISP next-hops are declared. Everything
above it — the endpoint registry and the measured paths — is derived on read
from that policy plus what the collectors see, so saving it re-derives them.
Nothing is deleted by a policy change; objects simply stop being derived.
