package backend

import (
	"context"
	"time"

	"netops/backend/collectors"
	"netops/backend/topology"
)

// topology_path_trace.go — attach per-hop TRACEROUTE measurements to the nodes on a
// Path Trace view, alongside the STAMP enrichment (topology_path_stamp.go). STAMP is
// measured per DESTINATION, so intermediate hops STAMP never targets show "—" even
// when the traceroute collector measured them. Traceroute measures every responding
// hop on the way to a destination, keyed by the hop's own IP:
//
//   - RTT: published to VictoriaMetrics as probe_hop_rtt_ms{dst,method,ttl,hop,
//     probe="traceroute"} (collectors/traceroute.go traceAll) — queried here folded
//     by the `hop` label.
//   - Loss: the collector computes per-hop loss but does NOT publish it as a VM
//     series; it travels only in the PathResult hop list (the probe-paths store that
//     /api/probe/paths serves). We read it from currentProbePaths — a real
//     measurement over a different transport, never a fabricated number.
//
// Values land in node.Metrics as trace_rtt_ms / trace_loss_pct, written independently
// of any stamp_* keys — the UI decides precedence (STAMP first, traceroute fallback).
// A hop no trace ever saw simply carries no trace_* keys (honest "—").

// traceSample is one hop IP's folded traceroute measurement.
type traceSample struct {
	rtt, loss       float64
	hasRTT, hasLoss bool
}

// traceHopMaxAge bounds how old a stored PathResult may be before its per-hop values
// are ignored (a prober that stopped must not keep painting stale numbers).
const traceHopMaxAge = 15 * time.Minute

// traceByHop builds hop-IP → traceroute sample from the two real transports:
// the VM per-hop RTT series and the probe-paths store (RTT fill + loss). Both are
// best-effort with bounded IO (vmInstant carries a 15s timeout; the paths store is
// a local/file/kv read) — a missing source just leaves fields unset.
func (s *server) traceByHop(ctx context.Context) map[string]traceSample {
	var vm []vmSample
	// Fold to the best (min) recent RTT per hop across dst/method/ttl — the same
	// "best RTT" semantics the collector itself uses per hop.
	if got, err := s.vmInstant(ctx, `min by (hop) (last_over_time(probe_hop_rtt_ms[5m]))`); err == nil {
		vm = got
	}
	paths, err := s.currentProbePaths(ctx)
	if err != nil {
		paths = nil
	}
	return foldTraceByHop(vm, paths, time.Now())
}

// foldTraceByHop is the pure join: VM samples (RTT, keyed by the `hop` label) plus
// stored traces (RTT fill + per-hop loss). Folding rule across observations of the
// same hop: MIN for both RTT and loss — a hop's best evidence. Traceroute loss is
// control-plane loss (routers legitimately deprioritize ICMP generation), so taking
// the minimum across traces avoids crying wolf on a hop that answers fully in any
// one trace; a hop that drops probes in EVERY trace still shows its real loss.
func foldTraceByHop(vm []vmSample, paths []collectors.PathResult, now time.Time) map[string]traceSample {
	out := map[string]traceSample{}
	for _, sm := range vm {
		hop := sm.Labels["hop"]
		if hop == "" || sm.Value <= 0 {
			continue
		}
		ts := out[hop]
		if !ts.hasRTT || sm.Value < ts.rtt {
			ts.rtt, ts.hasRTT = sm.Value, true
		}
		out[hop] = ts
	}
	for _, p := range paths {
		if !p.TS.IsZero() && now.Sub(p.TS) > traceHopMaxAge {
			continue // stale trace — do not paint dead numbers
		}
		for _, h := range p.Hops {
			if h.IP == "" {
				continue // a "*" hop — nothing measured, nothing to attach
			}
			ts := out[h.IP]
			if h.RTTms > 0 && (!ts.hasRTT || h.RTTms < ts.rtt) {
				ts.rtt, ts.hasRTT = h.RTTms, true
			}
			if !ts.hasLoss || h.Loss < ts.loss {
				ts.loss, ts.hasLoss = h.Loss, true
			}
			out[h.IP] = ts
		}
	}
	return out
}

// enrichPathTrace stamps per-hop traceroute metrics onto the nodes that lie on the
// view's path (same matching contract as enrichPathStamp: only path nodes, matched
// by management IP). trace_* keys are written unconditionally next to any stamp_*
// keys — precedence is the UI's call. A hop with no trace sample is left untouched.
func enrichPathTrace(view *topology.View, byHop map[string]traceSample) {
	if view == nil || len(view.Path) == 0 || len(byHop) == 0 {
		return
	}
	onPath := make(map[string]bool, len(view.Path))
	for _, id := range view.Path {
		onPath[id] = true
	}
	for i := range view.Nodes {
		n := &view.Nodes[i]
		if !onPath[n.ID] {
			continue
		}
		ts, ok := byHop[hostOnly(n.MgmtIP)]
		if !ok {
			continue
		}
		if n.Metrics == nil {
			n.Metrics = map[string]float64{}
		}
		if ts.hasRTT {
			n.Metrics["trace_rtt_ms"] = ts.rtt
		}
		if ts.hasLoss {
			n.Metrics["trace_loss_pct"] = ts.loss
		}
	}
}
