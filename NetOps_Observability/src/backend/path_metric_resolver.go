package main

import "context"

// path_metric_resolver.go — the ONE source-agnostic path-metric resolver
// (#3 of the WAN path-metrics program).
//
// Every place that needs a path/circuit's CURRENT latency/jitter/loss/QoE reads
// it from here, so the measurement-source fallback and the `source` provenance
// are identical everywhere (path-health API, topology path-trace, the WAN
// circuit table). The ladder, highest-fidelity first:
//
//	IP-SLA / SD-WAN controller (on-device, ingested)   ← reserved, no query yet
//	STAMP (RFC 8762, two-way)                           ← SP profile; dormant in enterprise
//	wan-echo (SD-WAN/BFD-style source-bound echo)       ← the enterprise default
//	synthetic ICMP                                       ← legacy service check
//	traceroute-TCP (path/fault companion)               ← last-resort latency only
//
// "Absent tier → next tier" falls out of the first-with-data-wins fold: in
// enterprise STAMP has no series so wan-echo wins; enable STAMP for SP and it
// takes over with no code change. Keyed by destination host (port stripped),
// the common identity across probe_*{dst}, circuit_*{dst}, synthetic_*{dst} and
// traceroute probe_hop_rtt_ms{dst}.

// PathSource is the measurement method that produced a metric (provenance).
type PathSource string

const (
	SrcIPSLA      PathSource = "ipsla"      // on-device IP SLA / SD-WAN controller (reserved)
	SrcSTAMP      PathSource = "stamp"      // RFC 8762 two-way active probe (SP)
	SrcEcho       PathSource = "echo"       // wan-echo source-bound circuit probe
	SrcSynthetic  PathSource = "icmp"       // synthetic ICMP service check
	SrcTraceroute PathSource = "traceroute" // traceroute-TCP path measurement
	SrcNone       PathSource = ""
)

// Label is the customer-facing name (no raw tokens in the UI — see the
// customer-facing-language rule).
func (p PathSource) Label() string {
	switch p {
	case SrcIPSLA:
		return "IP SLA"
	case SrcSTAMP:
		return "STAMP"
	case SrcEcho:
		return "Active echo"
	case SrcSynthetic:
		return "ICMP"
	case SrcTraceroute:
		return "Traceroute"
	default:
		return "—"
	}
}

// ResolvedPathMetric is one destination's current SLA with per-field provenance.
type ResolvedPathMetric struct {
	Latency, Jitter, Loss, QoE              float64
	HasLatency, HasJitter, HasLoss, HasQoE  bool
	LatencySource, JitterSource, LossSource PathSource
}

// Source is the headline provenance: whatever produced the latency, else the
// loss (a total-loss path has no latency sample but is still a real observation).
func (m *ResolvedPathMetric) Source() PathSource {
	if m.LatencySource != SrcNone {
		return m.LatencySource
	}
	return m.LossSource
}

// resolveCurrentByDst runs the cascade once (a fixed handful of VM vector
// queries) and returns host → resolved current metric. Best-effort: a query
// error or a missing tier simply leaves the lower tier (or nothing) in place.
func (s *server) resolveCurrentByDst(ctx context.Context) map[string]*ResolvedPathMetric {
	out := map[string]*ResolvedPathMetric{}
	get := func(h string) *ResolvedPathMetric {
		m := out[h]
		if m == nil {
			m = &ResolvedPathMetric{}
			out[h] = m
		}
		return m
	}
	// foldFirst applies a query for one field in priority order: a dst already
	// filled by a higher tier is left untouched, so the first tier with data wins.
	foldLatency := func(query string, src PathSource) {
		samples, err := s.vmInstant(ctx, query)
		if err != nil {
			return
		}
		for _, sm := range samples {
			h := hostOnly(sm.Labels["dst"])
			if h == "" {
				continue
			}
			if m := get(h); !m.HasLatency {
				m.Latency, m.HasLatency, m.LatencySource = sm.Value, true, src
			}
		}
	}
	foldJitter := func(query string, src PathSource) {
		samples, err := s.vmInstant(ctx, query)
		if err != nil {
			return
		}
		for _, sm := range samples {
			h := hostOnly(sm.Labels["dst"])
			if h == "" {
				continue
			}
			if m := get(h); !m.HasJitter {
				m.Jitter, m.HasJitter, m.JitterSource = sm.Value, true, src
			}
		}
	}
	foldLoss := func(query string, src PathSource) {
		samples, err := s.vmInstant(ctx, query)
		if err != nil {
			return
		}
		for _, sm := range samples {
			h := hostOnly(sm.Labels["dst"])
			if h == "" {
				continue
			}
			if m := get(h); !m.HasLoss {
				m.Loss, m.HasLoss, m.LossSource = sm.Value, true, src
			}
		}
	}
	foldQoE := func(query string, src PathSource) {
		samples, err := s.vmInstant(ctx, query)
		if err != nil {
			return
		}
		for _, sm := range samples {
			h := hostOnly(sm.Labels["dst"])
			if h == "" {
				continue
			}
			if m := get(h); !m.HasQoE {
				m.QoE, m.HasQoE = sm.Value, true
			}
		}
	}

	// ── latency: STAMP → echo → synthetic ICMP → traceroute (path-derived) ──
	// (IP-SLA/SD-WAN ingest would prepend here once that tier exists.)
	foldLatency(`quantile_over_time(0.95, probe_rtt_ms[5m])`, SrcSTAMP)
	foldLatency(`quantile_over_time(0.95, circuit_latency_ms[5m])`, SrcEcho)
	foldLatency(`quantile_over_time(0.95, synthetic_icmp_rtt_ms[5m])`, SrcSynthetic)
	// Traceroute e2e proxy: the slowest hop on the TCP trace to that dst. Coarse
	// (not strictly the destination hop) — last resort, tagged as such.
	foldLatency(`max(quantile_over_time(0.95, probe_hop_rtt_ms{method="tcp"}[5m])) by (dst)`, SrcTraceroute)

	// ── jitter: STAMP pdv → echo (only these two measure it) ──
	foldJitter(`quantile_over_time(0.95, probe_pdv_ms[5m])`, SrcSTAMP)
	foldJitter(`quantile_over_time(0.95, circuit_jitter_ms[5m])`, SrcEcho)

	// ── loss: STAMP → echo → synthetic ICMP → traceroute (1 - reachability) ──
	foldLoss(`avg_over_time(probe_loss_pct[5m])`, SrcSTAMP)
	foldLoss(`avg_over_time(circuit_loss_pct[5m])`, SrcEcho)
	foldLoss(`avg_over_time(synthetic_icmp_loss_pct[5m])`, SrcSynthetic)
	foldLoss(`(1 - avg_over_time(probe_path_reached{method="tcp"}[5m])) * 100`, SrcTraceroute)

	// ── QoE: only the echo probe scores it today ──
	foldQoE(`avg_over_time(circuit_qoe[5m])`, SrcEcho)

	return out
}

// resolvedSources returns the distinct sources present, in priority order —
// handy for a "measured by: STAMP, echo" summary.
func resolvedSources(ms map[string]*ResolvedPathMetric) []PathSource {
	seen := map[PathSource]bool{}
	for _, m := range ms {
		if src := m.Source(); src != SrcNone {
			seen[src] = true
		}
	}
	var out []PathSource
	for _, s := range []PathSource{SrcIPSLA, SrcSTAMP, SrcEcho, SrcSynthetic, SrcTraceroute} {
		if seen[s] {
			out = append(out, s)
		}
	}
	return out
}
