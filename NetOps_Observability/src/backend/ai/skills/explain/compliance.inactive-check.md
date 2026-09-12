---
topic: compliance.inactive-check
question: What does an inactive check mean?
keywords: inactive check, data source not connected, cannot assess not compliant
---
An inactive check means its data source is not connected, so the check did not
run. That is "cannot assess", never "compliant". Drift checks need the Source
of Truth connected; SNMP policy checks need credential profiles assigned to
devices; the known-exploited check needs the vulnerability advisory feed. Each
inactive row names its own reason — connect that source and the check starts
producing verdicts on the next pass.
