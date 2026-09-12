---
topic: path.segment-delay
question: How is added latency per segment worked out?
keywords: segment delay, added latency, stamp delta, where delay enters
---
Each hop's own measured delay is subtracted from the next hop's, so the
difference is the latency that segment adds. The segment with the largest
difference is where delay enters the path. It needs both ends measured: a
segment with an unmeasured hop at either end shows nothing rather than an
estimate. Small negative differences happen and mean the two measurements are
within noise of each other, not that a link removed delay.
