---
topic: queue.read-failed
question: The queue could not be read — what does that mean?
keywords: queue read failed, queue unavailable, queue unknown
---
When the Action Queue cannot be read, the state of your correlated incidents
is unknown — not empty. The page says so rather than drawing a green zero,
because an empty queue and an unanswered API look identical to a person and
mean opposite things. Retry, and if it persists check the platform's own
health under Administration.
