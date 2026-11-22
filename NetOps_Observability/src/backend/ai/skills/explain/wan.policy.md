---
topic: wan.policy
question: What does the measurement policy control?
keywords: measurement policy, wan device pattern, derived registry, policy saved
---
The policy, under Administration › Discovery › WAN circuits, says what to
measure WAN interfaces to and which devices look like WAN routers. It holds the fallback anchors, the ISP next-hops — declaring one
for a single interface also confirms that interface as WAN — whether ports
facing a WAN router are offered as possible, and the device-name hint. The
hint only suggests where to look; it never makes a port WAN on its own.
Everything else is derived on read, so saving the policy re-derives it.
