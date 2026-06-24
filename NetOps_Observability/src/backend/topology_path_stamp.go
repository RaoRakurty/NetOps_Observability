package main

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

// stampByDst queries the active-measurement metrics and folds them into one sample
// per destination host. Best-effort: a missing metric/series leaves its field unset
// (a query error returns whatever was gathered so far, never a hard failure).
func (s *server) stampByDst(ctx context.Context) map[string]stampSample {
	out := map[string]stampSample{}
	apply := func(query string, set func(a *stampSample, v float64)) {
		samples, err := s.vmInstant(ctx, query)
		if err != nil {
			return
		}
		for _, sm := range samples {
			h := hostOnly(sm.Labels["dst"])
			if h == "" {
				continue
			}
			cur := out[h]
			set(&cur, sm.Value)
			out[h] = cur
		}
	}
	// STAMP: 5-min p95 latency/jitter/delay + 5-min avg loss (mirrors path-health).
	apply(`quantile_over_time(0.95, probe_rtt_ms[5m])`, func(a *stampSample, v float64) { a.rtt = v; a.hasRTT = true })
	apply(`quantile_over_time(0.95, probe_owd_ms[5m])`, func(a *stampSample, v float64) { a.owd = v; a.hasOWD = true })
	apply(`quantile_over_time(0.95, probe_pdv_ms[5m])`, func(a *stampSample, v float64) { a.pdv = v; a.hasPDV = true })
	apply(`avg_over_time(probe_loss_pct[5m])`, func(a *stampSample, v float64) { a.loss = v; a.hasLoss = true })
	// ICMP synthetic fallback for a hop with no STAMP probe (latency + loss only).
	apply(`quantile_over_time(0.95, synthetic_icmp_rtt_ms[5m])`, func(a *stampSample, v float64) {
		if !a.hasRTT {
			a.rtt = v
			a.hasRTT = true
		}
	})
	apply(`avg_over_time(synthetic_icmp_loss_pct[5m])`, func(a *stampSample, v float64) {
		if !a.hasLoss {
			a.loss = v
			a.hasLoss = true
		}
	})
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
