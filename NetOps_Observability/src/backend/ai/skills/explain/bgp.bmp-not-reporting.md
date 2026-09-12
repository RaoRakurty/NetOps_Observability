---
topic: bgp.bmp-not-reporting
question: Why is nothing reporting neighbour state?
keywords: bmp off, feature_bmp, no exporter, neighbour state missing, bgp peer oid
---
Two feeds can tell this page about your own BGP sessions and neither is
answering. The BMP receiver is switched off (FEATURE_BMP), so no router can push
its Adj-RIB-In to the platform; and no device is exposing the BGP peer-state
counter over SNMP or gNMI. To fix it, enable the receiver and point a router's
BMP export at it, or enable the BGP peer OID in the device profile. Until then
this is an absent feed, not a healthy fleet.
