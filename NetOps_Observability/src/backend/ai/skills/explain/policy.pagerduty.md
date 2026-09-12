---
topic: policy.pagerduty
question: How does PagerDuty paging work?
keywords: pagerduty policy, page per root cause, deduplicated, auto resolve
---
One page per correlated root cause, deduplicated: the same incident is updated
in place rather than paged again, and it is auto-resolved when the fault
clears. The policy's urgency maps to page severity, with 1 meaning critical.
Raw alerts never page directly — only a correlated root cause that passes the
policy does. Connect the routing key in the PagerDuty paging connection above.
