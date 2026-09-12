---
topic: bgp.peer-sources
question: What does the "Reported by" column mean?
keywords: bmp, device metric, adj-rib-in, reported by, two witnesses, peer state source
---
Two witnesses, never conflated. A row reported by BMP comes from one of your own
routers pushing its Adj-RIB-In to the platform; it is the only source that
carries the reason for a change and the announce and withdraw counters. A row
reported by a device metric is an SNMP or gNMI sample of the same session seen
from outside, where only "established" counts as up. Where both describe the
same router and neighbour, the router's own report wins.
