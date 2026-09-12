---
topic: backup.off-host
question: Why does an off-host copy matter?
keywords: off-host copy, remote destination, offsite, second copy, disaster recovery
---
A copy on the same machine as the live data protects you from deleting an index
by mistake. It protects you from nothing else. If that disk, that host or that
site is lost, the data and every copy of it are lost together — which is not
disaster recovery, it is a slower kind of the same outage. Setting a
destination points the whole bundle somewhere else: another mounted device, a
file server, or object storage. Until one is set this reads "Not set", and the
verdict above treats it as the gap it is.
