---
topic: quarantine.retention
question: How long is an envelope held?
keywords: quarantine retention, deleted after a window, retention days
---
Envelopes are deleted by the index retention policy after a bounded window —
`QUARANTINE_RETENTION_DAYS`, 30 days on the shipped configuration. This page
reports the oldest envelope it can see, not the window installed on this
cluster, so a short oldest age can mean either a quiet week or a short
retention. Re-attribution is deliberate break-glass and is not a control here;
the runbook carries the procedure.
