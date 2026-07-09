package main

// Scope health score (#69 front-page §4) — the Health-strip backend.
// Design rule (owner): HONEST BEFORE IMPRESSIVE. The score blends multiple signal
// classes for a scope (global / site); with fewer than 2 live classes it returns
// INSUFFICIENT_TELEMETRY rather than a confident verdict from one source. Probes
// alone never make the network look unhealthy. Every score is explainable
// (per-contribution points) — never a black-box. Reuses the Path Behavior Health
// primitives (path_health.go: lossSeverity / severityPctDistance / hinge-style).
//
//   GET /api/health/score?scope=global|site&id=<site>
//
// Each class fetcher is best-effort + independent: a dead correlation service or a
// missing metric drops that class (not live), it never errors the strip
// (non-goal: the dashboard must not depend on correlation availability).

import (
	"context"
	"errors"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// signal-class weights (front-page §4 defaults). Availability is non-negotiable;
// path (customer probes) and trusted correlation rank above raw device counters.
var healthClassWeights = map[string]float64{
	"availability":  3.0,
	"path_health":   2.5,
	"correlation":   2.0,
	"device_health": 1.5,
}

type healthContribution struct {
	SignalClass string  `json:"signal_class"`
	Entity      string  `json:"entity"`
	Badness     float64 `json:"badness"`
	Points      int     `json:"points"`
	Reason      string  `json:"reason"`
	Timestamp   string  `json:"timestamp,omitempty"`
}

// healthClassResult is one signal class's verdict for the scope. Live=false means
// the class had no data (or its source was unreachable) — excluded from coverage.
type healthClassResult struct {
	Class    string
	Live     bool
	Stale    bool
	Badness  float64 // class-level badness (worst meaningful within the class), 0..2
	Contribs []healthContribution
}

type HealthScoreResp struct {
	Scope             string               `json:"scope"`
	ID                string               `json:"id,omitempty"`
	Score             *int                 `json:"score"` // null when insufficient telemetry
	Band              string               `json:"band"`
	Confidence        string               `json:"confidence"`
	CoverageStatus    string               `json:"coverage_status"`
	SignalClassesLive []string             `json:"signal_classes_live"`
	Contributions     []healthContribution `json:"contributions"`
	StaleInputs       []string             `json:"stale_inputs"`
	UpdatedAt         string               `json:"updated_at"`
}

func healthBandFromScore(s int) string {
	switch {
	case s >= 80:
		return "healthy"
	case s >= 60:
		return "watch"
	case s >= 40:
		return "degraded"
	default:
		return "critical"
	}
}

func reduceConfStr(c string) string {
	switch c {
	case "high":
		return "medium"
	case "medium":
		return "medium_low"
	default:
		return "low"
	}
}

// hingeN: 0 below lo, linear lo→hi, 1 above hi. Used for utilization/CPU/mem where
// a signal is only "bad" near saturation.
func hingeN(v, lo, hi float64) float64 {
	if v <= lo {
		return 0
	}
	if v >= hi {
		return 1
	}
	return (v - lo) / (hi - lo)
}

// aggregateHealthScore is the PURE core (unit-tested): coverage honesty, weighted
// blend with the anti-averaging floor (so a hotspot isn't averaged away), bands,
// confidence, and per-contribution points that sum to the score deficit.
func aggregateHealthScore(scope, id string, classes []healthClassResult, nowISO string) HealthScoreResp {
	// Init to empty (never nil): a nil slice serializes to JSON null, and the UI
	// reads .length on these — null would throw and blank the page. API contract:
	// list fields are always arrays.
	live := []healthClassResult{}
	liveNames := []string{}
	stale := []string{}
	for _, c := range classes {
		if !c.Live {
			continue
		}
		live = append(live, c)
		liveNames = append(liveNames, c.Class)
		if c.Stale {
			stale = append(stale, c.Class)
		}
	}
	sort.Strings(liveNames)
	sort.Strings(stale)

	// Coverage honesty: < 2 live classes ⇒ INSUFFICIENT_TELEMETRY (no confident
	// score from one source — this is what makes probe-only return insufficient).
	if len(live) < 2 {
		return HealthScoreResp{
			Scope: scope, ID: id, Score: nil, Band: "insufficient_telemetry",
			Confidence: "low", CoverageStatus: "INSUFFICIENT_TELEMETRY",
			SignalClassesLive: liveNames, Contributions: []healthContribution{},
			StaleInputs: stale, UpdatedAt: nowISO,
		}
	}

	var num, den, maxB float64
	for _, c := range live {
		w := healthClassWeights[c.Class]
		num += w * c.Badness
		den += w
		if c.Badness > maxB {
			maxB = c.Badness
		}
	}
	blend := 0.0
	if den > 0 {
		blend = math.Max(num/den, 0.8*maxB) // floor: worst class can't be averaged away
	}
	blend = clampF(blend, 0, 1)
	score := int(math.Round(100 * (1 - blend)))
	deficit := 100 - score

	// distribute the deficit across contributions by weighted badness
	var wsum float64
	for _, c := range live {
		w := healthClassWeights[c.Class]
		for _, ct := range c.Contribs {
			wsum += w * ct.Badness
		}
	}
	contribs := []healthContribution{}
	for _, c := range live {
		w := healthClassWeights[c.Class]
		for _, ct := range c.Contribs {
			if wsum > 0 {
				ct.Points = int(math.Round(float64(deficit) * (w * ct.Badness) / wsum))
			}
			ct.Badness = math.Round(ct.Badness*100) / 100
			contribs = append(contribs, ct)
		}
	}
	sort.SliceStable(contribs, func(i, j int) bool { return contribs[i].Points > contribs[j].Points })

	conf := "medium_low"
	switch {
	case len(live) >= 4:
		conf = "high"
	case len(live) >= 3:
		conf = "medium"
	}
	if len(stale) > 0 {
		conf = reduceConfStr(conf)
	}

	return HealthScoreResp{
		Scope: scope, ID: id, Score: &score, Band: healthBandFromScore(score),
		Confidence: conf, CoverageStatus: "OK", SignalClassesLive: liveNames,
		Contributions: contribs, StaleInputs: stale, UpdatedAt: nowISO,
	}
}

// ── handler ──────────────────────────────────────────────────────────────────

func (s *server) handleHealthScore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	if scope == "" {
		scope = "global"
	}
	if scope != "global" && scope != "site" {
		writeError(w, http.StatusBadRequest, errors.New("scope must be global or site"))
		return
	}
	site := sanitizeCHText(r.URL.Query().Get("id"))
	ctx := r.Context()

	// best-effort, independent class fetchers (a dead source → class not live)
	classes := []healthClassResult{
		s.fetchAvailabilityClass(ctx, site),
		s.fetchDeviceHealthClass(ctx, site),
		s.fetchPathHealthClass(ctx),
		s.fetchCorrelationClass(r, site),
	}
	resp := aggregateHealthScore(scope, site, classes, time.Now().UTC().Format(time.RFC3339))
	writeJSON(w, http.StatusOK, resp)
}

// qVecBy runs a VM vector query and returns value-by-label-key (e.g. "device").
// Best-effort: an error yields an empty map + ok=false (class then not live).
func (s *server) qVecBy(ctx context.Context, query, key string) (map[string]float64, bool) {
	samples, err := s.vmInstant(ctx, query)
	if err != nil {
		return nil, false
	}
	out := map[string]float64{}
	for _, sm := range samples {
		if k := sm.Labels[key]; k != "" {
			if sm.Value > out[k] {
				out[k] = sm.Value
			}
		}
	}
	return out, true
}

// qVecBy2 is qVecBy keyed by two labels, taking the max value seen per (k1,k2)
// pair. Returns nil (not an empty map) when the query fails, so callers can
// treat "unreachable" and "no series" identically (both yield no lookups).
func (s *server) qVecBy2(ctx context.Context, query, k1, k2 string) map[[2]string]float64 {
	samples, err := s.vmInstant(ctx, query)
	if err != nil {
		return nil
	}
	out := map[[2]string]float64{}
	for _, sm := range samples {
		a, b := sm.Labels[k1], sm.Labels[k2]
		if a == "" || b == "" {
			continue
		}
		k := [2]string{a, b}
		if v, seen := out[k]; !seen || sm.Value > v {
			out[k] = sm.Value
		}
	}
	return out
}

// fetchAvailabilityClass: admin-up interfaces that are oper-down, per device.
func (s *server) fetchAvailabilityClass(ctx context.Context, site string) healthClassResult {
	res := healthClassResult{Class: "availability"}
	total, ok1 := s.qVecBy(ctx, `count by (device) (device_if_admin_status == 1)`, "device")
	down, ok2 := s.qVecBy(ctx, `count by (device) (device_if_admin_status == 1 and device_if_oper_status != 1)`, "device")
	if !ok1 || len(total) == 0 {
		return res // not live
	}
	res.Live = true
	for dev, tot := range total {
		d := down[dev]
		if d <= 0 || tot <= 0 {
			continue
		}
		b := clampF(d/tot, 0, 1)
		if b > res.Badness {
			res.Badness = b
		}
		if b >= 0.34 {
			res.Contribs = append(res.Contribs, healthContribution{
				SignalClass: "availability", Entity: dev, Badness: b,
				Reason: strconv.Itoa(int(d)) + " of " + strconv.Itoa(int(tot)) + " interfaces down on " + dev,
			})
		}
	}
	_ = ok2
	return res
}

// fetchDeviceHealthClass: utilization / errors+discards / CPU / mem, per device.
func (s *server) fetchDeviceHealthClass(ctx context.Context, site string) healthClassResult {
	res := healthClassResult{Class: "device_health"}
	type dh struct {
		b      float64
		reason string
	}
	devs := map[string]*dh{}
	bump := func(dev string, b float64, reason string) {
		if dev == "" {
			return
		}
		d := devs[dev]
		if d == nil {
			d = &dh{}
			devs[dev] = d
		}
		if b > d.b {
			d.b = b
			d.reason = reason
		}
	}
	live := false
	if util, ok := s.qVecBy(ctx, `max by (device) (rate(device_if_in_octets[5m])*8 / ((device_if_speed > 0)*1000000))`, "device"); ok && len(util) > 0 {
		live = true
		for dev, u := range util {
			bump(dev, hingeN(u, 0.70, 0.95), "Link utilization "+pct1(u)+" on "+dev)
		}
	}
	if errs, ok := s.qVecBy(ctx, `max by (device) (rate(device_if_in_errors[5m])+rate(device_if_out_errors[5m])+rate(device_if_in_discards[5m])+rate(device_if_out_discards[5m]))`, "device"); ok {
		if len(errs) > 0 {
			live = true
		}
		for dev, e := range errs {
			bump(dev, hingeN(e, 0.1, 5), "Interface errors/discards "+round2s(e)+"/s on "+dev)
		}
	}
	if cpu, ok := s.qVecBy(ctx, `max by (device) (device_cpu_percent)`, "device"); ok {
		if len(cpu) > 0 {
			live = true
		}
		for dev, c := range cpu {
			bump(dev, hingeN(c, 70, 95), "CPU "+pct0(c)+" on "+dev)
		}
	}
	if mem, ok := s.qVecBy(ctx, `max by (device) (device_mem_percent)`, "device"); ok {
		for dev, mv := range mem {
			bump(dev, hingeN(mv, 75, 95), "Memory "+pct0(mv)+" on "+dev)
		}
	}
	res.Live = live
	for dev, d := range devs {
		if d.b > res.Badness {
			res.Badness = d.b
		}
		if d.b >= 0.40 {
			res.Contribs = append(res.Contribs, healthContribution{
				SignalClass: "device_health", Entity: dev, Badness: d.b, Reason: d.reason,
			})
		}
	}
	return res
}

// fetchPathHealthClass: customer path latency/jitter/loss via probes, reusing the
// PBH severity curves. GUARDRAIL: internal monitoring targets (env list) are
// excluded so internal self-probes never drive customer health. (Full scope/
// authority-based exclusion is V1 when probe metrics carry those labels.)
func (s *server) fetchPathHealthClass(ctx context.Context) healthClassResult {
	res := healthClassResult{Class: "path_health"}
	internal := map[string]bool{}
	for _, t := range strings.Split(envOr("HEALTH_INTERNAL_PROBE_TARGETS", ""), ",") {
		if t = strings.TrimSpace(t); t != "" {
			internal[t] = true
		}
	}
	curLat, ok := s.qVecBy(ctx, `quantile_over_time(0.95, probe_rtt_ms[5m])`, "dst")
	baseP50, _ := s.qVecBy(ctx, `quantile_over_time(0.50, probe_rtt_ms[7d])`, "dst")
	baseP99, _ := s.qVecBy(ctx, `quantile_over_time(0.99, probe_rtt_ms[7d])`, "dst")
	loss, _ := s.qVecBy(ctx, `avg_over_time(probe_loss_pct[5m])`, "dst")
	if !ok {
		return res
	}
	considered := 0
	for dst, lat := range curLat {
		if internal[dst] || internal[hostOnly(dst)] {
			continue // internal monitoring target — excluded from customer health
		}
		considered++
		var b float64
		if sev, sevOK := severityPctDistance(lat, baseP50[dst], baseP99[dst]); sevOK {
			b = sev
		}
		if lb := lossSeverity(loss[dst], 0); lb > b {
			b = lb
		}
		if b > res.Badness {
			res.Badness = b
		}
		if b >= 0.40 {
			res.Contribs = append(res.Contribs, healthContribution{
				SignalClass: "path_health", Entity: dst, Badness: b,
				Reason: "Path to " + dst + " worse than its normal baseline",
			})
		}
	}
	res.Live = considered > 0 // only live if there is a customer-facing path to judge
	return res
}

// fetchCorrelationClass: ONLY trusted, customer-facing RCA objects drive health —
// confirmed/suspected, grounded, cross-plane, not low-authority, not debug-excluded,
// not undetermined. Weak/probe-only/internal objects are excluded (guardrail).
// Best-effort: a ClickHouse/engine outage drops the class, never errors the strip.
func (s *server) fetchCorrelationClass(r *http.Request, site string) healthClassResult {
	res := healthClassResult{Class: "correlation"}
	// Bounded read (2026-07-09 incident, part 2): fold narrow keys only — pulling
	// o.hypotheses (~5.7KB/row) through corr_objects_latest's LIMIT-1-BY sort, and
	// GROUP BY'ing the ENTIRE corr_edges table to decorate 200 rows, are the exact
	// shapes that pinned ClickHouse. Wide columns + edges are fetched keyed by the
	// picked (id, version) pairs.
	const hp = "o.hypotheses,'ranking','hypotheses',1,'verdict'"
	sql := `
WITH picked AS (
     SELECT correlation_id, version, created_at FROM (
          SELECT tenant_id, correlation_id, version, created_at, state, verdict_tier, top_hypothesis
            FROM netops.corr_objects
           ORDER BY tenant_id, correlation_id, version DESC
           LIMIT 1 BY tenant_id, correlation_id
     )
      WHERE state='open' AND verdict_tier IN ('confirmed','suspected')
        AND top_hypothesis != 'undetermined'
      ORDER BY created_at DESC
      LIMIT 200
)
SELECT toString(o.correlation_id) AS id, o.top_hypothesis AS hyp, o.top_confidence AS conf,
       o.verdict_tier AS tier, toString(o.created_at) AS created_at,
       coalesce(e.grounding,'none') AS grounding,
       length(JSONExtract(` + hp + `,'modality_coverage','Array(String)')) AS planes,
       length(JSONExtract(` + hp + `,'excluded_debug_probes','Array(String)')) > 0 AS debug_excluded,
       length(JSONExtract(` + hp + `,'low_authority_probe_scopes','Array(String)')) > 0 AS low_authority
  FROM netops.corr_objects AS o
  LEFT JOIN (SELECT correlation_id, version, arrayStringConcat(arraySort(groupUniqArray(grounding_kind)),'+') AS grounding
               FROM netops.corr_edges
              WHERE (correlation_id, version) IN (SELECT correlation_id, version FROM picked)
              GROUP BY correlation_id, version) AS e
    ON e.correlation_id = o.correlation_id AND e.version = o.version
 WHERE (o.correlation_id, o.version) IN (SELECT correlation_id, version FROM picked)
 FORMAT JSON`
	rows, err := s.chRows(r, sql)
	if err != nil {
		return res // engine/CH down → class not live (strip still scores from infra)
	}
	res.Live = true
	for _, row := range rows {
		grounding, _ := row["grounding"].(string)
		if grounding == "" || grounding == "none" {
			continue // ungrounded → not trusted
		}
		if truthy(row["debug_excluded"]) || truthy(row["low_authority"]) {
			continue // internal/test or low-authority → excluded from customer health
		}
		if asFloat(row["planes"]) < 2 {
			continue // single-plane → not strong enough to drive customer health
		}
		conf := asFloat(row["conf"])
		if conf > res.Badness {
			res.Badness = conf
		}
		hyp, _ := row["hyp"].(string)
		created, _ := row["created_at"].(string)
		res.Contribs = append(res.Contribs, healthContribution{
			SignalClass: "correlation", Entity: hyp, Badness: conf,
			Reason: "Trusted RCA: " + hyp + " (" + asString(row["tier"]) + ")", Timestamp: created,
		})
	}
	return res
}

// ── small helpers ────────────────────────────────────────────────────────────

func pct0(v float64) string {
	return strconv.FormatFloat(v, 'f', 0, 64) + "%"
}
func pct1(v float64) string { // v is a 0..1 fraction
	return strconv.FormatFloat(v*100, 'f', 1, 64) + "%"
}
func round2s(v float64) string { return strconv.FormatFloat(math.Round(v*100)/100, 'f', -1, 64) }
func hostOnly(dst string) string {
	if i := strings.LastIndex(dst, ":"); i > 0 {
		return dst[:i]
	}
	return dst
}
func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		return x == "1" || x == "true"
	}
	return false
}
func asFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	}
	return 0
}
func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
