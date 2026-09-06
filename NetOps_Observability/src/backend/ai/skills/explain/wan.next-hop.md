---
topic: wan.next-hop
question: What is an ISP next-hop?
keywords: isp next hop, ownership handoff, seam, provider handoff, next hop override
---
The next-hop is the first address on the provider's side of the circuit — where
your ownership of the path ends and the ISP's begins. Declaring it gives that
interface something meaningful to measure to: loss or latency to the next-hop
is yours to fix, and loss beyond it is the provider's. Declare one per device,
or per single interface where a device has several circuits. Without one, the
interface falls back to a reachability anchor.
