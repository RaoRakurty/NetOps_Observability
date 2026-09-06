---
topic: rsc.closure-time
question: Why is ticket closure time unavailable?
keywords: ticket closure, resolution time, itsm workflow, servicenow jira pagerduty
---
The median time until the ticket or workflow closed — the repair clock, not the
investigation clock. It needs timestamps Correlix does not generate itself:
ServiceNow, Jira, PagerDuty or an operator workflow. Until one of those is
connected the card reads "Not available" and says "ITSM workflow required",
rather than inferring a closure that never happened. Connect a ticketing
integration under Administration and the metric fills in from the next incident
onward; it is not backfilled, because the evidence for past closures does not
exist here.
