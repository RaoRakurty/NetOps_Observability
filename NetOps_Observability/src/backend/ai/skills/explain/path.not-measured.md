---
topic: path.not-measured
question: Why does a hop say not measured?
keywords: not measured yet, no probe reaches this hop, missing hop metric, em dash metric
---
No probe currently produces that number for that hop, so the cell is empty
rather than filled with a plausible one. It is a statement about coverage, not
about the hop: an unmeasured hop is not a healthy hop and not a broken one.
Each empty cell names what is missing — no probe targets this hop's address, no
series exists for its interface, or the value is not in the collection profile
yet — so the fix is always a collection change, never a re-read.
