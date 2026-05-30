package collectors

import "time"

// NETCONF is an SSH/YANG collector. Full NETCONF RPCs need an SSH client
// (golang.org/x/crypto/ssh, outside the zero-dependency scope); the stdlib
// layer probes the NETCONF SSH port over TCP (default 830) for reachability
// and records latency.
func NewNETCONF(targets TargetFunc) Collector {
	return newPoller("netconf", 120*time.Second, 830, tcpProbe, byProtocol(targets, "netconf"))
}
