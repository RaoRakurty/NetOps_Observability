---
topic: queue.next-action
question: Where does the recommended next action come from?
keywords: next action, recommended action, what to do next
---
The next action on an Action Queue row is derived from the incident's own
state, not from a template: what the verdict says, whether an owner exists,
whether evidence is missing, and whether a ticket is due. A suspected or
blocked incident is held — its impact is not confirmed, so the action is to
gather evidence rather than to escalate. A confirmed one is eligible for a
ticket and for escalation.
