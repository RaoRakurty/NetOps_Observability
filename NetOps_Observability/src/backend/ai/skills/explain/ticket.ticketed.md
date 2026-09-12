---
topic: ticket.ticketed
question: What counts as ticketed?
keywords: ticketed incidents, synced to itsm
---
Ticketed on the Command Center counts incidents that have been pushed to your
ITSM and acknowledged by it. The push is asynchronous — an outbox worker opens
the case shortly after it is queued — so a very recent request may not be
counted yet. If a push errored it is counted under Sync failed instead, never
here.
