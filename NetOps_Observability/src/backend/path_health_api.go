package main

// Path Behavior Health API — wraps the pure scoring core (path_health.go) with a
// VictoriaMetrics percentile fetcher. Design: docs/design/path-behavior-health.md.
//
//   GET /api/paths/health  → [{path_id, health_state, score, confidence, baseline,
//                              current, severities, reason, likely_fault_domain,
//                              evidence}], worst-first.
//
// Efficient: a fixed handful of VECTOR queries (one value per path series) rather
// than per-path round-trips. Per-path baselines come live from quantile_over_time;
// sparse/new paths fall back to a class baseline then a conservative global one
// (the §4 cascade, tiers 3→4→5). Infra-scoped (probes are operator-run telemetry).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type vmSample struct {
	Labels map[string]string
	Value  float64
}

// vmInstant runs a VictoriaMetrics instant query and returns one sample per series.
func (s *server) vmInstant(ctx context.Context, query string) ([]vmSample, error) {
	base := envOr("VICTORIA_URL", envOr("METRICS_URL", "http://victoria:8428"))
	endpoint := strings.TrimRight(base, "/") + "/api/v1/query?query=" + url.QueryEscape(query)
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := backendHTTPClient(15 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("victoriametrics status %d", resp.StatusCode)
	}
	var out struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  [2]any            `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return nil, err
	}
	samples := make([]vmSample, 0, len(out.Data.Result))
	for _, r := range out.Data.Result {
		v := 0.0
		if str, ok := r.Value[1].(string); ok {
			v, _ = strconv.ParseFloat(str, 64)
		}
		samples = append(samples, vmSample{Labels: r.Metric, Value: v})
	}
	return samples, nil
}

// durationToken validates a PromQL range token from env (e.g. "7d") so it can be
// interpolated safely; falls back to "7d" on anything malformed.
func durationToken(v, def string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	n := 0
	for i, c := range v {
		switch {
		case c >= '0' && c <= '9':
			n++
		case (c == 's' || c == 'm' || c == 'h' || c == 'd' || c == 'w') && i == len(v)-1 && n > 0:
		default:
			return def
		}
	}
	return v
}

// pathAcc accumulates the metrics for one path across the VM queries.
type pathAcc struct {
	agent, dst                     string
	source                         PathSource // winning measurement source (provenance #3)
	curLat, curJit, curLoss        float64
	hasLat, hasJit, hasLoss        bool
	latP50, latP99, jitP50, jitP99 float64
	count                          float64
}

func isPrivateHost(host string) bool {
	if strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "192.168.") || strings.HasPrefix(host, "127.") {
		return true
	}
	if strings.HasPrefix(host, "172.") {
		// 172.16.0.0 – 172.31.255.255
		var a, b int
		if _, err := fmt.Sscanf(host, "172.%d.%d", &a, &b); err == nil && a >= 16 && a <= 31 {
			return true
		}
	}
	return !strings.Contains(host, ".") // bare hostname → treat as internal
}

// classifyPathClass is the coarse cold-start class for tier-4 fallback. With no
// path metadata yet, we split internal (LAN/DC) from external (cloud/SaaS) by the
// destination address shape — refined when SoT/cloud enrichment lands.
func classifyPathClass(dst string) string {
	host := dst
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	if isPrivateHost(host) {
		return "internal"
	}
	return "external"
}

// classBaseline returns the conservative tier-4 baseline for a path class.
func classBaseline(class string) PathBaseline {
	switch class {
	case "internal":
		return PathBaseline{Source: baselineClass, Latency: metricBaseline{P50: 5, P99: 40}, Jitter: metricBaseline{P50: 2, P99: 15}}
	default: // external / cloud / SaaS
		return PathBaseline{Source: baselineClass, Latency: metricBaseline{P50: 40, P99: 200}, Jitter: metricBaseline{P50: 5, P99: 50}}
	}
}

func (s *server) handlePathsHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	ctx := r.Context()
	win := durationToken(envOr("PATH_HEALTH_BASELINE_WINDOW", "7d"), "7d")
	probeInterval := 30.0
	if v, err := strconv.ParseFloat(envOr("PROBE_INTERVAL_SEC", "30"), 64); err == nil && v > 0 {
		probeInterval = v
	}

	paths := map[string]*pathAcc{}
	get := func(dst string) *pathAcc {
		k := hostOnly(dst)
		a := paths[k]
		if a == nil {
			a = &pathAcc{dst: dst}
			paths[k] = a
		}
		return a
	}
	// apply runs one VM vector query and folds each series into its path by
	// destination host. Best-effort (a missing metric leaves its fields unset).
	apply := func(query string, f func(a *pathAcc, v float64)) {
		samples, err := s.vmInstant(ctx, query)
		if err != nil {
			return
		}
		for _, sm := range samples {
			dst := sm.Labels["dst"]
			if dst == "" {
				continue
			}
			f(get(dst), sm.Value)
		}
	}

	// current latency / jitter / loss come from the ONE source-agnostic resolver
	// (#3): STAMP → wan-echo → synthetic ICMP → traceroute, with provenance. The
	// path row carries the winning source so the UI shows HOW it was measured.
	for h, m := range s.resolveCurrentByDst(ctx) {
		a := paths[h]
		if a == nil {
			a = &pathAcc{dst: h}
			paths[h] = a
		}
		a.curLat, a.hasLat = m.Latency, m.HasLatency
		a.curJit, a.hasJit = m.Jitter, m.HasJitter
		a.curLoss, a.hasLoss = m.Loss, m.HasLoss
		a.source = m.Source()
		a.agent = string(a.source) // back-compat: the `agent` field now names the source
	}
	// per-path baseline percentiles over the baseline window
	apply(`quantile_over_time(0.50, probe_rtt_ms[`+win+`])`, func(a *pathAcc, v float64) { a.latP50 = v })
	apply(`quantile_over_time(0.99, probe_rtt_ms[`+win+`])`, func(a *pathAcc, v float64) { a.latP99 = v })
	apply(`quantile_over_time(0.50, synthetic_icmp_rtt_ms[`+win+`])`, func(a *pathAcc, v float64) {
		if a.latP50 == 0 {
			a.latP50 = v
		}
	})
	apply(`quantile_over_time(0.99, synthetic_icmp_rtt_ms[`+win+`])`, func(a *pathAcc, v float64) {
		if a.latP99 == 0 {
			a.latP99 = v
		}
	})
	apply(`quantile_over_time(0.50, probe_pdv_ms[`+win+`])`, func(a *pathAcc, v float64) { a.jitP50 = v })
	apply(`quantile_over_time(0.99, probe_pdv_ms[`+win+`])`, func(a *pathAcc, v float64) { a.jitP99 = v })
	apply(`count_over_time(probe_rtt_ms[`+win+`])`, func(a *pathAcc, v float64) { a.count = v })
	apply(`count_over_time(synthetic_icmp_rtt_ms[`+win+`])`, func(a *pathAcc, v float64) {
		if a.count == 0 {
			a.count = v
		}
	})

	type item struct {
		PathID      string         `json:"path_id"`
		Agent       string         `json:"agent"`
		Dst         string         `json:"dst"`
		Source      string         `json:"source"`       // measurement provenance (#3)
		SourceLabel string         `json:"source_label"` // customer-facing source name
		Current     map[string]any `json:"current"`
		Base        map[string]any `json:"baseline"`
		PathHealth
	}
	// V1 tier 2: hour-of-week precomputed baselines (path_health_baselines.go).
	// Best-effort — nil (feature off / CH down / table empty) falls through to
	// tiers 3–5 exactly as the MVP behaved. Tier 1 (route+hour) is a declared
	// stub until probes carry route labels (see path_health_baselines.go).
	hourBase := s.fetchHourBaselines(r, time.Now().UTC())

	items := make([]item, 0, len(paths))
	for k, a := range paths {
		days := a.count * probeInterval / 86400
		perPath := PathBaseline{
			Source:      baselinePath,
			Latency:     metricBaseline{P50: a.latP50, P99: a.latP99},
			Jitter:      metricBaseline{P50: a.jitP50, P99: a.jitP99},
			SampleCount: int(a.count),
			Days:        days,
			RouteStable: true, // no route-change signal in MVP → treat as stable
		}
		classBase := classBaseline(classifyPathClass(a.dst))
		classBase.SampleCount = int(a.count)
		classBase.Days = days
		hb, hasHour := hourBase[k]
		// §4 cascade, strongest→weakest; the class fallback is always last so a
		// path never fails to score. SelectBaseline applies the readiness gates.
		base, _ := SelectBaseline([]BaselineCandidate{
			{Baseline: hb, Available: hasHour},
			{Baseline: perPath, Available: a.latP99 > a.latP50},
			{Baseline: classBase, Available: true},
		})
		cur := PathCurrent{
			LatencyP95_5m: a.curLat, JitterP95_5m: a.curJit, LossPct5m: a.curLoss,
			HasLatency: a.hasLat, HasJitter: a.hasJit, HasLoss: a.hasLoss,
		}
		h := ScorePathHealth(cur, base, weightsForClass(""))
		items = append(items, item{
			PathID: k, Agent: a.agent, Dst: a.dst,
			Source: string(a.source), SourceLabel: a.source.Label(),
			Current: map[string]any{
				"latency_p95_5m": round1(a.curLat), "jitter_p95_5m": round1(a.curJit), "loss_pct_5m": round2(a.curLoss),
			},
			Base: map[string]any{
				"source": base.Source, "source_label": base.Source.sourceLabel(),
				"window": win, "sample_count": base.SampleCount,
				"latency_p50": round1(base.Latency.P50), "latency_p99": round1(base.Latency.P99),
				"jitter_p50": round1(base.Jitter.P50), "jitter_p99": round1(base.Jitter.P99),
			},
			PathHealth: h,
		})
	}
	// worst-first
	sort.Slice(items, func(i, j int) bool { return items[i].Score > items[j].Score })

	writeJSON(w, http.StatusOK, map[string]any{"paths": items, "count": len(items)})
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }
func round2(v float64) float64 { return float64(int(v*100+0.5)) / 100 }
