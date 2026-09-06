---
topic: device.neighbors
question: Where do a device's neighbours come from?
keywords: lldp cdp bgp-ls, layer 2 neighbours, adjacency discovery, topology links
---
Layer-2 neighbours are learned from the discovery protocols the device itself
runs — LLDP, CDP, or the link-state topology a BGP-LS session exports. Each row
is an adjacency the device reported, with the local and remote ports named. No
neighbours observed means none of those protocols reported one here: they may
be disabled on the device, or the neighbour may not be managed. It is not a
claim that the device has no links.
