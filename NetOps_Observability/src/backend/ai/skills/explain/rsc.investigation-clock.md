---
topic: rsc.investigation-clock
question: What are the investigation clock and the repair clock?
keywords: investigation clock, repair clock, detection correlation isolation, recovery resolution
---
The NOC Recovery Scorecard deliberately separates two clocks. The investigation
clock is how fast incidents were detected, correlated and isolated — work that
is Correlix's to speed up. The repair clock is recovery and resolution, which
wait on owner action, provider repair or workflow evidence, and are often not
yours to shorten at all. Reading them together is how a scorecard turns into an
argument: a fast investigation clock beside a slow repair clock says the NOC
found the fault quickly and then waited, which is a different problem from
never having found it.
