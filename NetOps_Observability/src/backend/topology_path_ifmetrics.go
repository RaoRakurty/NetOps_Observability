package backend

import (
	"context"

	"netops/backend/topology"
)

// topology_path_ifmetrics.go — #85. Attach the remaining per-hop path metrics
// (bandwidth, throughput, reliability, MTU) to the EDGES of a Path Trace view.
// These are interface-level facts, so — exactly like Utilization — they join on
// (device, ifName) via canonIface. A metric with no series leaves its field unset
// (the UI renders an honest "—"); we never fabricate a number. MTU stays unset
// until the ifMtu OID is polled (added to the SNMP profile, no lab data yet).

// ifaceMetric is one interface's joined facts. has* flags distinguish "0" (a real
// measured zero) from "absent" (no series → honest "—").
type ifaceMetric struct {
	bwMbps, thrMbps, reliability, mtu float64
	hasBW, hasThr, hasRel, hasMTU     bool
}

// pathIfaceMetrics queries VictoriaMetrics for the interface facts, keyed by
// (device, canonIface). Best-effort: an unreachable VM or missing series yields an
// empty/partial map, never an error (mirrors stampByDst).
func (s *server) pathIfaceMetrics(ctx context.Context) map[[2]string]ifaceMetric {
	// Bandwidth — interface link speed (device_if_speed is in Mbps, per the
	// utilization formula that divides octet-bits by speed*1e6).
	bw := canonIfaceMap(s.qVecBy2(ctx, `max by (device, ifName) (device_if_speed)`, "device", "ifName"))
	// Throughput — busiest-direction octet rate in Mbps (consistent with Utilization,
	// which is the busiest direction as a fraction of speed).
	inThr := canonIfaceMap(s.qVecBy2(ctx, `rate(device_if_in_octets[5m])*8/1e6`, "device", "ifName"))
	outThr := canonIfaceMap(s.qVecBy2(ctx, `rate(device_if_out_octets[5m])*8/1e6`, "device", "ifName"))
	// Reliability inputs — oper-status (1=up) and the error/discard vs packet rates.
	oper := canonIfaceMap(s.qVecBy2(ctx, `max by (device, ifName) (device_if_oper_status)`, "device", "ifName"))
	errDisc := canonIfaceMap(s.qVecBy2(ctx,
		`rate(device_if_in_errors[5m]) + rate(device_if_out_errors[5m]) + rate(device_if_in_discards[5m]) + rate(device_if_out_discards[5m])`,
		"device", "ifName"))
	pkts := canonIfaceMap(s.qVecBy2(ctx,
		`rate(device_if_in_ucast_pkts[5m]) + rate(device_if_out_ucast_pkts[5m])`,
		"device", "ifName"))
	mtu := canonIfaceMap(s.qVecBy2(ctx, `max by (device, ifName) (device_if_mtu)`, "device", "ifName"))

	out := map[[2]string]ifaceMetric{}
	get := func(k [2]string) ifaceMetric { return out[k] }
	put := func(k [2]string, m ifaceMetric) { out[k] = m }

	for k, v := range bw {
		m := get(k)
		m.bwMbps, m.hasBW = v, true
		put(k, m)
	}
	for k := range union(inThr, outThr) {
		m := get(k)
		m.thrMbps, m.hasThr = maxf(inThr[k], outThr[k]), true
		put(k, m)
	}
	for k := range mtu {
		m := get(k)
		m.mtu, m.hasMTU = mtu[k], true
		put(k, m)
	}
	// Reliability = oper-status × error-free packet ratio, computed where the
	// interface reports an oper-status (the authoritative "is this link alive" gate).
	for k, up := range oper {
		m := get(k)
		m.reliability, m.hasRel = reliabilityScore(up, errDisc[k], pkts[k]), true
		put(k, m)
	}
	return out
}

// reliabilityScore — 0..100. Down (oper != up) ⇒ 0. Up ⇒ the error-free ratio:
// 100 × (1 − (errors+discards) / (packets+errors+discards)). No traffic ⇒ 100
// (a healthy idle link, not a fault). Pure (unit-tested).
func reliabilityScore(operUp, errDiscRate, pktRate float64) float64 {
	if operUp < 1 {
		return 0
	}
	bad := errDiscRate
	if bad < 0 {
		bad = 0
	}
	denom := pktRate + bad
	if denom <= 0 {
		return 100 // up + no observed traffic → not a fault
	}
	rel := (1 - bad/denom) * 100
	if rel < 0 {
		rel = 0
	}
	if rel > 100 {
		rel = 100
	}
	return rel
}

// enrichPathIfMetrics stamps the interface facts onto every edge of the view by
// matching the edge's endpoints (device, port) — source preferred, target as
// fallback — to the joined metrics. Pure (no I/O): the caller supplies the map.
func enrichPathIfMetrics(view *topology.View, byIface map[[2]string]ifaceMetric) {
	if view == nil || len(byIface) == 0 {
		return
	}
	for i := range view.Edges {
		e := &view.Edges[i]
		src := [2]string{e.Source, canonIface(e.SourcePort)}
		tgt := [2]string{e.Target, canonIface(e.TargetPort)}
		m, ok := byIface[src]
		if !ok {
			m, ok = byIface[tgt]
		}
		if !ok {
			continue
		}
		if m.hasBW && e.BandwidthMbps == 0 {
			e.BandwidthMbps = m.bwMbps
		}
		if m.hasThr && e.ThroughputMbps == 0 {
			e.ThroughputMbps = m.thrMbps
		}
		if m.hasRel && e.Reliability == 0 {
			e.Reliability = m.reliability
		}
		if m.hasMTU && e.MTU == 0 {
			e.MTU = m.mtu
		}
	}
}

// union returns the set of keys present in either map (values irrelevant).
func union(a, b map[[2]string]float64) map[[2]string]struct{} {
	out := make(map[[2]string]struct{}, len(a)+len(b))
	for k := range a {
		out[k] = struct{}{}
	}
	for k := range b {
		out[k] = struct{}{}
	}
	return out
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
