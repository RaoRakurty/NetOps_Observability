---
topic: lane.skipped-run
question: What does a skipped outcome mean?
keywords: skipped run, last real result, run already in flight
---
Skipped means a run was already in flight when this one was due, so the lane
did not start a second pass. It refuses to blank a row it did not re-measure,
which is why the row still carries the numbers from the last real result rather
than zeros. Read the "last run" time beside it: if that is old, the lane is
falling behind, not idle.
