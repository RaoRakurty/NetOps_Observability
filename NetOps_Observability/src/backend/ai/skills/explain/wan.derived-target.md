---
topic: wan.derived-target
question: What is a derived target?
keywords: derived target, measured to, measurement target, next hop anchor neighbour
---
Every WAN interface needs something to measure to, and the platform derives it
rather than asking you to type one per interface. First choice is a neighbour
the device sees on the wire, which keeps the whole measured path inside your
estate. Next is the ISP next-hop you declared, which measures up to the point
where the path becomes the provider's. Last is a public reachability anchor,
which proves the interface can reach the internet and nothing more. An
interface with none of these is not measured, and says so.
