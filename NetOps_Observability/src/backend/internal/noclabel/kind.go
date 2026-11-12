// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package noclabel

import "strings"

// Kind is a compact humanizer for signal kinds (server side mirror of the UI's
// kindLabel for the common families; the UI re-labels for display, this is the
// stored title fallback).
func Kind(kind string) string {
	base := strings.TrimSuffix(kind, "_clear")
	switch base {
	case "bgp_adjacency_change", "bgp_state_anomaly":
		return "BGP neighbor change"
	case "ospf_adjacency_change":
		return "OSPF neighbor change"
	case "isis_adjacency_change":
		return "IS-IS neighbor change"
	case "link_state_change":
		return "Link up/down"
	case "lldp_neighbor_change":
		return "Neighbor change"
	case "stp_topology_change":
		return "Spanning-tree change"
	case "probe_loss":
		return "Packet loss"
	case "probe_rtt_anomaly", "probe_latency_departure":
		return "Response-time change"
	case "if_errors":
		return "Interface errors"
	case "if_util_high":
		return "High link utilization"
	case "if_metric_anomaly":
		// RCA v2 §3.1: the observed condition that titles P-3E0400. It is a
		// counter/rate departure on an interface, NOT a state change.
		return "Interface metric anomaly"
	case "mac_flap":
		return "MAC address flap"
	case "device_alarm":
		// A generic device alarm: never a routing or link event (§3.7).
		return "Device alarm"
	case "device_resource_anomaly":
		return "Device CPU/memory change"
	case "flow_volume_anomaly":
		return "Traffic volume change"
	case "sot_drift":
		return "Inventory drift"
	case "topology_change":
		return "Topology change"
	case "security_posture":
		return "Security hardening finding"
	case "security_exposure":
		return "Security exposure finding"
	case "security_signal":
		return "Security detection"
	}
	title := strings.ReplaceAll(base, "_", " ")
	if title == "" {
		return "Event"
	}
	return strings.ToUpper(title[:1]) + title[1:]
}
