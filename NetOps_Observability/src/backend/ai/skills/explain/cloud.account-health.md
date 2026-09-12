---
topic: cloud.account-health
question: Why are connection and delivery judged separately?
keywords: connection health, data delivery, telemetry silent, configured account
---
Because they fail independently and the fix is different. A connection can be
perfectly healthy while no telemetry arrives — a permission missing at the
source, a log export never enabled — and that reads as "connection OK, no data
arriving", not as a broken connection. A configured account also never
disappears from this list for lack of data: it exists because it was
configured, not because something arrived.
