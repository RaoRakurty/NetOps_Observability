---
topic: tunnels.discovery
question: How are VPN and overlay tunnels discovered?
keywords: tunnel discovery, ipsec, gre, vti, if-mib, tunnel-mib, snmp walk, tunnel latency empty
---
Tunnel interfaces — IPsec, GRE and VTI — are found by walking the standard
IF-MIB and TUNNEL-MIB over SNMP on each device, so a tunnel appears here as
soon as the device reports the interface. That walk gives state and counters
only. Latency, loss and QoE stay empty until an SD-WAN controller or an
active-probe source reports them for that tunnel; an empty column means no one
has measured it, not that the tunnel is healthy.
