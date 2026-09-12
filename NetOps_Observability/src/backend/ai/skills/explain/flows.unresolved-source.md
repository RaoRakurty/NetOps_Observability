---
topic: flows.unresolved-source
question: Why does a flow row say Source not resolved?
keywords: source not resolved, no source column, legacy rollup, far end only
---
This row was rolled up before the source side was recorded, so only its far
end is named. It is a different fact from "the source is the unknown
application": nothing was ever stored to name, rather than stored and
unclaimed. Rows collected after the source column landed carry both sides.
The bytes and flows on the row are still a real measurement — only the
initiating side is unavailable, so the row cannot be attributed to a source
application.
