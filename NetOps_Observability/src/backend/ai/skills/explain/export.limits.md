---
topic: export.limits
question: What do the log export limits do?
keywords: export limits, anti exfiltration, download link ttl, export rate
---
They bound how much log data can leave the platform: exports per minute, rows
and bytes per export, how long one may run, how wide a time window it may
cover, and how long a download link stays valid. They exist to make bulk
exfiltration visibly hard, not to slow ordinary work. Changes apply live with
no restart, and only the platform owner can make them — a tenant must not be
able to raise its own caps.
