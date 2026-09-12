---
topic: overlay.config-drift
question: What does the config-drift overlay show?
keywords: config drift overlay, golden config, running config diverged, intent
---
Flagged nodes are devices whose running configuration no longer matches the
intended or golden configuration recorded for them. Drift is a fact about the
text, not a verdict about the network: a drifted device can be working
perfectly, and an undrifted one can still be misconfigured if the golden copy
is wrong. A device with no golden copy is not flagged, because there is nothing
to compare against.
