---
topic: path.hop-interface
question: Where do the per-hop interface numbers come from?
keywords: bandwidth ifspeed, throughput octet rate, reliability, mtu, hop interface metrics
---
They are read from the hop's own interface, not from the probe. Bandwidth is
the interface's reported speed. Throughput is its measured octet rate.
Reliability combines operational state with the error-free ratio. MTU is the
interface's configured value. Each shows a dash when there is no series for
that interface, and the tooltip says which is missing — usually a hop the
platform does not poll, or a value not yet in the collection profile.
