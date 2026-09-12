---
topic: overlay.historical-diff
question: What does the historical-diff overlay show?
keywords: historical diff, added removed changed, snapshot comparison, topology diff
---
It compares the current graph against an earlier snapshot and marks what was
added, removed or changed across the selected window. "Removed" means not
re-observed since the snapshot, which can be a decommission or a collector that
stopped — the overlay reports the difference and does not decide which. Pair it
with the coverage figure before concluding that something left the network.
