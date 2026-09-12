---
topic: overlay.health
question: What does the health overlay show?
keywords: health overlay, node health ring, health bands, topology health
---
Node rings carry health — good, warning, critical, in maintenance, or unknown —
and every colour is paired with a glyph so the state survives a colour-blind
reading and a screenshot. Edges keep their own relationship style underneath,
so a healthy node on a dashed link still reads as an inferred link. Unknown is
its own band, not a quiet pass: it means nothing has reported on that object
recently.
