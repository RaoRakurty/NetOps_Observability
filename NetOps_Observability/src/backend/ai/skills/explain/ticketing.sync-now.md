---
topic: ticketing.sync-now
question: What does Sync now do?
keywords: sync now, reconcile, drift sweep, two-way integrations
---
It reads the current state of every two-way integration for this tenant and
records what changed on the provider's side — a drift sweep. It opens no
ticket and closes none. It only touches bidirectional providers, so it can
honestly answer zero even while outbound integrations exist.
