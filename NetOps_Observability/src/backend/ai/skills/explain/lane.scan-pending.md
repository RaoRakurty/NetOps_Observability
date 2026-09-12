---
topic: lane.scan-pending
question: Why has my scan not appeared?
keywords: scan pending, scan queued, no completed run recorded
---
The request was accepted and the run is queued; no completed run has been
recorded yet. It has not failed — the result has not arrived. The console stops
polling after a bounded number of tries rather than claiming a scan finished it
never saw. Read the row again in a moment. If a scan is already queued or
running for the tenant, a second request is refused instead of stacking up.
