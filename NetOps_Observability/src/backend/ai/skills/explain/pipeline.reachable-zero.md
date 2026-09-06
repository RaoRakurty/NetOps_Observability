---
topic: pipeline.reachable-zero
question: Monitored devices but zero reachable — what does that mean?
keywords: reachable zero, monitored but unreachable, snmp unreachable, collector healthy, creds acl
---
When monitored is above zero but reachable is zero, the collector is healthy
and the devices are unreachable — it is not a pipeline failure. The collector
counted the targets it was configured with, tried them, and got nothing back.
The usual causes are credentials (a rotated SNMP community or v3 user), an ACL
or firewall between the collector and the devices, or the devices being down.
Start at the device end, not at Correlix. The reverse reading — monitored at
zero — means nothing was configured for collection at all.
