---
topic: wifi.stale
question: What does stale mean on a wireless row?
keywords: stale wireless row, not seen last poll, freshness window
---
The connector has not re-observed that object inside its freshness window, so
the row is history rather than a live claim. It is kept and marked instead of
being deleted, because an object that stopped being reported is evidence in
itself — usually a controller that lost the access point, or a poll that is
failing. It is not a statement that the access point is down.
