---
topic: lane.counters
question: What do the lane counters count?
keywords: lane counters, totals since start, refused grounding, dead letter
---
These are totals for the lane process since it started, not for the last run —
restarting the platform resets them. The first four count work that succeeded.
The last five count evidence that never reached the engine: refused grounding,
dropped by the per-run cap, publish attempts exhausted, held in the dead-letter
lane, and no durable copy anywhere. Anything counted there is evidence a story
could have used and did not get, so a non-zero value is a gap in what the
engine could correlate.
