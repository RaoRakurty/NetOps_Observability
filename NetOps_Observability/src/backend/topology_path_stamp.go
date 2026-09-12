// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"

	"netops/backend/topology"
)

// topology_path_stamp.go — attach per-hop active-measurement metrics to the nodes
// on a Path Trace view: STAMP first (latency=rtt, jitter=pdv, delay=owd, + loss),
// ICMP synthetic as a latency/loss fallback. STAMP is measured per destination
// (`probe_*_ms{dst}`), so we match each hop to a probe whose dst is that hop's
// address and stamp the hop's metrics map. A hop with no probe reaching it simply
// carries no stamp_* keys (the UI renders an honest "—"); we never fabricate a
// per-hop number. Values are the prober→hop measurement (STAMP is end-to-end by
// nature); the per-segment delta between consecutive hops is the segment's share.

type stampSample struct {
	rtt, owd, pdv, loss             float64
	hasRTT, hasOWD, hasPDV, hasLoss bool
}

// (hostOnly — strip a :port from a probe dst so it matches a device address — is
// defined in health_score.go and shared here.)

// stampByDst folds the active-measurement metrics into one sample per destination
// host, via the shared source-agnostic resolver (#3): latency/jitter/loss cascade
// STAMP → wan-echo → synthetic ICMP → traceroute, so a path-trace hop picks up
// whatever method measured it — not STAMP only. One-way delay (OWD) is
// STAMP-specific (no resolver field), so it's filled directly where present.
// Best-effort: a missing metric/series leaves its field unset (honest "—").
func (s *server) stampByDst(ctx context.Context, f []string) map[string]stampSample {
	// SEC (2026-08-04): scoped like its sibling gatherTopoMetrics — an unscoped
	// read let two tenants that both run a `core-sw1` render each other's
	// metrics onto their own path (topology_view.go:86-91 documents the
	// original defect; these three enrichers were missed by that fix).

	out := map[string]stampSample{}
	for h, m := range s.resolveCurrentByDst(ctx, f) {
		ss := stampSample{}
		if m.HasLatency {
			ss.rtt, ss.hasRTT = m.Latency, true
		}
		if m.HasJitter {
			ss.pdv, ss.hasPDV = m.Jitter, true
		}
		if m.HasLoss {
			ss.loss, ss.hasLoss = m.Loss, true
		}
		out[h] = ss
	}
	// OWD is STAMP-only (two-way timestamps) — no resolver field; fill directly.
	if samples, err := s.vmInstantScoped(ctx, `quantile_over_time(0.95, probe_owd_ms[5m])`, f); err == nil {
		for _, sm := range samples {
			h := hostOnly(sm.Labels["dst"])
			if h == "" {
				continue
			}
			ss := out[h]
			ss.owd, ss.hasOWD = sm.Value, true
			out[h] = ss
		}
	}
	return out
}

// enrichPathStamp stamps per-hop active-measurement metrics onto the nodes that lie
// on the view's path. Only path nodes are touched; a node whose address matches no
// probe dst is left untouched (no stamp_* keys → honest "—" in the UI).
func enrichPathStamp(view *topology.View, byDst map[string]stampSample) {
	if view == nil || len(view.Path) == 0 || len(byDst) == 0 {
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
		ss, ok := byDst[hostOnly(n.MgmtIP)]
		if !ok {
			continue
		}
		if n.Metrics == nil {
			n.Metrics = map[string]float64{}
		}
		if ss.hasRTT {
			n.Metrics["stamp_rtt_ms"] = ss.rtt
		}
		if ss.hasOWD {
			n.Metrics["stamp_owd_ms"] = ss.owd
		}
		if ss.hasPDV {
			n.Metrics["stamp_pdv_ms"] = ss.pdv
		}
		if ss.hasLoss {
			n.Metrics["stamp_loss_pct"] = ss.loss
		}
	}
}
