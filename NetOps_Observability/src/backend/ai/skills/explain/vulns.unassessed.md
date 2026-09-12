---
topic: vulns.unassessed
question: Why can a device not be assessed?
keywords: unassessed device, version unknown, cannot be assessed, coverage gap
---
CVE matching needs two facts read agentlessly over SNMP: a known vendor from
sysObjectID, and an OS product and version parsed from sysDescr. A device
missing either is invisible to matching, so the absence of findings on it means
unknown, not safe. Fix reachability or the credential profile so the device
answers those objects, and it joins the assessed fleet on the next poll.
