---
topic: kpi.rca-blocked
question: What blocks a root-cause analysis?
keywords: rca blocked, blocked incident, missing evidence streams
---
Blocked on the Command Center means the analysis stopped because an evidence
stream it needs is not arriving — no flows for the path, no syslog from the
device, no metrics in the window. The engine will not guess past a gap, so the
incident waits. The row lists which streams are missing; fixing the collection
usually unblocks the verdict without any further human analysis.
