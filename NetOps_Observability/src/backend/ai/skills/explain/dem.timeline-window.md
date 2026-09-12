---
topic: dem.timeline-window
question: Why does the timeline axis span the entries?
keywords: timeline axis, incident window, scrubber axis
---
When an incident carries no declared window, the timeline has nothing to scale
against, so its axis spans the recorded entries instead. The consequence
matters: an axis drawn that way cannot show how much of the real window
produced no entry at all, so gaps in coverage become invisible. Entries
themselves are unaffected.
