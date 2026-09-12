---
topic: path.no-seam
question: Why does the trace say no seam link was discovered?
keywords: no seam link, on-prem to cloud path, cloud endpoint no path, direct connect vpn adjacency, seam not discovered
---
The two endpoints sit on opposite sides of the boundary between your own
network and the cloud, and nothing has been discovered that joins them. A seam
link is real data: a VPN, Direct Connect or ExpressRoute row that names the
address it terminates on, matched to a device you manage at that address. Where
the provider returned no peer address, or that address belongs to no device in
inventory, there is no adjacency to walk. The platform will not draw the hop
anyway: a line nobody observed is what makes a path map untrustworthy. Add the
terminating device to inventory with the address the cloud reports, or check the
connector may read that VPN or Direct Connect detail.
