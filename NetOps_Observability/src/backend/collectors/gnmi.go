package collectors

import "time"

// GNMI is a gRPC/OpenConfig collector. Full gNMI subscription needs a
// gRPC+protobuf client (outside the zero-dependency scope); the stdlib-only
// layer probes the gNMI port over TCP (default 9339) for reachability and
// records latency. Point it at 57400 etc. via the device address (host:port).
func NewGNMI(targets TargetFunc) Collector {
	return newPoller("gnmi", 60*time.Second, 9339, tcpProbe, byProtocol(targets, "gnmi"))
}
