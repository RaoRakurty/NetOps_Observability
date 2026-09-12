---
topic: ticketing.empty-outbox
question: Does an empty outbox mean nothing was ticketed?
keywords: empty outbox, nothing in flight, proof a ticket was filed
---
No. The outbox holds work that is on its way out, so it empties as delivery
succeeds. An empty outbox means nothing is currently in flight — it is not
evidence that a ticket was ever filed. The audit trail below is: it records
every ticket action for this tenant, in both directions, whether or not the
row is still in the outbox.
