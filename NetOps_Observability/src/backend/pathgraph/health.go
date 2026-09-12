// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pathgraph

// Path Behavior Health — adaptive, baseline-relative path scoring.
// Design: docs/design/path-behavior-health.md.
//
// This file is the PURE scoring core: severity curves, the weighted blend with
// an anti-averaging floor, health bands, confidence rules, the baseline-source
// priority cascade, and NOC-friendly reason/evidence/owner strings. It does no
// I/O so it is fully unit-tested (the §12 acceptance scenarios are the spec).
// The VM-percentile fetcher + /api/paths/health handler wrap this core.

import (
	"fmt"
	"math"
)

// ── enums ────────────────────────────────────────────────────────────────────

// BaselineSource — which tier of the priority cascade produced the baseline.
type BaselineSource string

const (
	BaselinePathRouteHour BaselineSource = "path_route_hour" // tier 1 (V1)
	BaselinePathHour      BaselineSource = "path_hour"       // tier 2 (V1)
	BaselinePath          BaselineSource = "path"            // tier 3 (MVP)
	BaselineClass         BaselineSource = "class"           // tier 4 (MVP)
	BaselineGlobal        BaselineSource = "global"          // tier 5 (MVP)
)

// Label is the NOC-facing wording for a baseline tier (no engine jargon).
func (b BaselineSource) Label() string {
	switch b {
	case BaselinePathRouteHour, BaselinePath:
		return "this path's normal behavior"
	case BaselinePathHour:
		return "this path at this time of week"
	case BaselineClass:
		return "similar paths"
	default:
		return "fallback baseline (new path)"
	}
}

// isFallback reports whether a baseline tier is a cold-start fallback (tier 4/5),
// which is inherently Low confidence.
func (b BaselineSource) isFallback() bool { return b == BaselineClass || b == BaselineGlobal }

type HealthState string

const (
	HealthHealthy  HealthState = "healthy"
	HealthWatch    HealthState = "watch"
	HealthDegraded HealthState = "degraded"
	HealthSevere   HealthState = "severe"
	// HealthUnknown: NOTHING was measurable in this window. It is not a band on
	// the same scale as the others — it means the question could not be asked.
	// Before it existed, zero measurable signals produced score 0, which
	// bandFor maps to "healthy", and the evidence builder then appended "All
	// measured signals are within this path's normal range" — an affirmative
	// all-clear manufactured from a blind probe lane. The heavy [5m] quantile
	// queries are the first to time out under VM load while the cheap ones
	// succeed, so this is the NORMAL partial-failure shape, not an edge case.
	HealthUnknown HealthState = "unknown"
)

type Confidence string

const (
	ConfLow       Confidence = "low"
	ConfMediumLow Confidence = "medium_low"
	ConfMedium    Confidence = "medium"
	ConfHigh      Confidence = "high"
)

// ── inputs ─────────────────────────────────────────────────────────────────

// MetricBaseline holds the learned percentiles for one metric on a path.
type MetricBaseline struct{ P50, P90, P95, P99 float64 }

// PathBaseline is the SELECTED baseline for a path plus its provenance — enough
// to compute severity AND to be honest about how much we trust it.
type PathBaseline struct {
	Source       BaselineSource
	Latency      MetricBaseline
	Jitter       MetricBaseline
	SampleCount  int
	Days         float64
	RouteStable  bool // V1: from route-fingerprint history (MVP: true, no route data)
	SparseProbe  bool // probe data has gaps in the window
	RouteChanged bool // V1: a route change observed recently (MVP: false)
}

// PathCurrent is the short-window (5-min p95) observation being scored. Has* flags
// distinguish "0" from "not measured" so a missing signal is excluded, not scored 0.
type PathCurrent struct {
	LatencyP95_5m float64
	JitterP95_5m  float64
	LossPct5m     float64
	LossBurst     float64 // 0..1 burstiness of loss; 0 when unknown
	HasLatency    bool
	HasJitter     bool
	HasLoss       bool
}

// Weights for the blend. Route instability has no source in MVP (weight unused
// until V1). confidence/congestion from the spec are intentionally NOT blend
// weights here: confidence is reported separately, congestion is not measured.
type Weights struct{ Loss, Latency, Jitter, Route float64 }

// WeightsForClass returns the blend profile for a path's traffic class. MVP has no
// traffic-class label, so callers pass "" → enterprise default. AI/GPU-sensitive
// paths weight loss + jitter higher (inference/RAG/agent flows feel loss and
// microbursts more than steady latency).
func WeightsForClass(class string) Weights {
	switch class {
	case "ai", "gpu", "inference":
		return Weights{Loss: 0.45, Latency: 0.15, Jitter: 0.25, Route: 0.05}
	default:
		return Weights{Loss: 0.40, Latency: 0.25, Jitter: 0.20, Route: 0.10}
	}
}

// ── result ───────────────────────────────────────────────────────────────────

type PathHealth struct {
	State          HealthState         `json:"health_state"`
	Score          float64             `json:"score"`
	Confidence     Confidence          `json:"confidence"`
	Severities     map[string]*float64 `json:"severities"` // nil value = signal unavailable
	BaselineSource BaselineSource      `json:"baseline_source"`
	Reason         string              `json:"reason"`
	FaultDomain    string              `json:"likely_fault_domain"`
	Evidence       []string            `json:"evidence"`
}

// ── severity curves ──────────────────────────────────────────────────────────

func ClampF(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// SeverityPctDistance = (current − p50) / (p99 − p50), clamped [0,2]. ok=false on
// a degenerate baseline (p99 ≤ p50) — that signal then contributes nothing rather
// than dividing by zero or fabricating a value.
func SeverityPctDistance(cur, p50, p99 float64) (float64, bool) {
	denom := p99 - p50
	if denom <= 0 {
		return 0, false
	}
	return ClampF((cur-p50)/denom, 0, 2), true
}

// LossSeverity is log-scaled (loss is non-linear in user pain: 1% ≈ disaster for
// voice/inference) plus a burstiness bump. Retransmits/ECN/queue-drops are not
// emitted today, so they are omitted (documented gap), not faked.
func LossSeverity(lossPct, burst float64) float64 {
	if lossPct < 0 {
		lossPct = 0
	}
	base := math.Log(1+lossPct/0.1) / math.Log(1+100.0/0.1)
	return ClampF(base+0.3*ClampF(burst, 0, 1), 0, 2)
}

// ── baseline cascade selection ─────────────────────────────────────────────────

// BaselineCandidate is one tier the caller was able to materialize, strongest
// first. SelectBaseline picks the strongest tier that meets its readiness gate.
type BaselineCandidate struct {
	Baseline  PathBaseline
	Available bool
}

// (readiness rule:)
// fallback tiers are always "ready" (they exist to be used, at Low confidence).
// BaselineReady gates a per-path tier on enough history.
func BaselineReady(b PathBaseline) bool {
	if b.Source.isFallback() {
		return true
	}
	return b.SampleCount >= 500 || b.Days >= 7
}

// SelectBaseline walks candidates strongest→weakest and returns the first ready
// one. Callers order them per the §4 cascade; a fallback candidate must always be
// last so the page never fails to score a path.
func SelectBaseline(cands []BaselineCandidate) (PathBaseline, bool) {
	for _, c := range cands {
		if c.Available && BaselineReady(c.Baseline) {
			return c.Baseline, true
		}
	}
	return PathBaseline{}, false
}

// ── confidence ───────────────────────────────────────────────────────────────

var confOrder = []Confidence{ConfLow, ConfMediumLow, ConfMedium, ConfHigh}

func reduceConfidence(c Confidence) Confidence {
	for i, v := range confOrder {
		if v == c && i > 0 {
			return confOrder[i-1]
		}
	}
	return ConfLow
}

// deriveConfidence applies the §5 rules: fallback baselines are Low; otherwise
// scale by history span, floored to Low under the sample/day minimum, then reduced
// one level for a recent route change or sparse probe data.
func deriveConfidence(b PathBaseline) Confidence {
	if b.Source.isFallback() {
		return ConfLow
	}
	var c Confidence
	switch {
	case b.Days >= 21 && b.RouteStable && !b.SparseProbe:
		c = ConfHigh
	case b.Days >= 10:
		c = ConfMedium
	case b.Days >= 3:
		c = ConfMediumLow
	default:
		c = ConfLow
	}
	if b.SampleCount < 100 || b.Days < 3 {
		c = ConfLow
	}
	if b.RouteChanged || b.SparseProbe {
		c = reduceConfidence(c)
	}
	return c
}

// ── bands + wording ──────────────────────────────────────────────────────────

// BandFor maps a blended score to its health band.
func BandFor(score float64) HealthState {
	switch {
	case score > 1.0:
		return HealthSevere
	case score >= 0.75:
		return HealthDegraded
	case score >= 0.40:
		return HealthWatch
	default:
		return HealthHealthy
	}
}

func buildReason(sev map[string]float64, src BaselineSource, state HealthState) string {
	if state == HealthHealthy {
		if src.isFallback() {
			return "This path looks normal so far — still learning its baseline (using a fallback for now)."
		}
		return "This path is performing within its normal range."
	}
	// Name the DOMINANT driver accurately and distinguish "elevated" (clearly high)
	// from "near its upper normal range" (only moderately above typical) — so we
	// never claim latency is elevated when it's actually inside the typical band.
	names := map[string]string{"latency": "Latency", "jitter": "Jitter", "loss": "Packet loss"}
	domK, domV := "", 0.0
	for k, v := range sev {
		if v > domV {
			domK, domV = k, v
		}
	}
	driver := names[domK]
	if driver == "" {
		driver = "Performance"
	}
	degree := "is near its upper normal range"
	if domV >= 0.6 || domK == "loss" { // any sustained loss is bad, not "near normal"
		degree = "is elevated"
	}
	switch src {
	case BaselineClass, BaselineGlobal:
		return fmt.Sprintf("%s %s, compared with similar paths (still learning this path's own baseline).", driver, degree)
	default:
		return fmt.Sprintf("%s %s, compared with this path's normal baseline.", driver, degree)
	}
}

// ── main scorer ──────────────────────────────────────────────────────────────

// ScorePathHealth combines the available per-signal severities into one
// baseline-relative score with an anti-averaging floor, then attaches band,
// confidence, NOC reason, evidence and (MVP) fault domain. Pure.
func ScorePathHealth(cur PathCurrent, base PathBaseline, w Weights) PathHealth {
	sev := map[string]float64{}
	if cur.HasLatency {
		if s, ok := SeverityPctDistance(cur.LatencyP95_5m, base.Latency.P50, base.Latency.P99); ok {
			sev["latency"] = s
		}
	}
	if cur.HasJitter {
		if s, ok := SeverityPctDistance(cur.JitterP95_5m, base.Jitter.P50, base.Jitter.P99); ok {
			sev["jitter"] = s
		}
	}
	if cur.HasLoss {
		sev["loss"] = LossSeverity(cur.LossPct5m, cur.LossBurst)
	}
	// route instability has no source in MVP — excluded from the blend.

	wmap := map[string]float64{"loss": w.Loss, "latency": w.Latency, "jitter": w.Jitter}
	var num, den, maxSev float64
	for k, s := range sev {
		num += wmap[k] * s
		den += wmap[k]
		if s > maxSev {
			maxSev = s
		}
	}
	score := 0.0
	measured := den > 0
	if measured {
		score = math.Max(num/den, 0.8*maxSev) // anti-averaging floor: one severe dim can't be averaged away
	}
	// No measurable signal is UNKNOWN, never healthy — see HealthUnknown.
	state := HealthUnknown
	if measured {
		state = BandFor(score)
	}

	// severities map with nil for unavailable signals (honest coverage)
	sevOut := map[string]*float64{}
	for _, k := range []string{"latency", "jitter", "loss", "route"} {
		if v, ok := sev[k]; ok {
			vv := math.Round(v*100) / 100
			sevOut[k] = &vv
		} else {
			sevOut[k] = nil
		}
	}

	return PathHealth{
		State:          state,
		Score:          math.Round(score*100) / 100,
		Confidence:     deriveConfidence(base),
		Severities:     sevOut,
		BaselineSource: base.Source,
		Reason:         buildReason(sev, base.Source, state),
		FaultDomain:    "insufficient_evidence", // MVP: end-to-end probe, no segment evidence (upgraded by traceroute/seam in V1)
		Evidence:       buildEvidence(cur, base, sev, state),
	}
}

// buildEvidence lists the concrete, NOC-readable facts behind the score.
func buildEvidence(cur PathCurrent, base PathBaseline, sev map[string]float64, state HealthState) []string {
	ev := []string{} // never nil — a nil slice serializes to JSON null (UI reads .length)
	if s, ok := sev["latency"]; ok && s >= 0.40 {
		ev = append(ev, fmt.Sprintf("Latency p95 (%.0f ms) vs this path's typical %.0f ms / bad %.0f ms",
			cur.LatencyP95_5m, base.Latency.P50, base.Latency.P99))
	}
	if s, ok := sev["jitter"]; ok && s >= 0.40 {
		ev = append(ev, fmt.Sprintf("Jitter p95 (%.0f ms) elevated vs typical %.0f ms", cur.JitterP95_5m, base.Jitter.P50))
	}
	if s, ok := sev["loss"]; ok && s >= 0.40 {
		ev = append(ev, fmt.Sprintf("Packet loss %.2f%% over the last 5 min", cur.LossPct5m))
	}
	if base.Source.isFallback() {
		ev = append(ev, "New path — comparing against a fallback baseline until it learns its own normal range")
	}
	if base.RouteChanged {
		ev = append(ev, "Route changed recently — confidence reduced")
	}
	if base.SparseProbe {
		ev = append(ev, "Probe data is sparse in this window — confidence reduced")
	}
	if state == HealthUnknown {
		// Say what is actually true: we could not measure, so we cannot claim.
		return append(ev, "No signal could be measured for this path in this window — "+
			"health is UNKNOWN, not healthy")
	}
	if len(ev) == 0 && state == HealthHealthy {
		ev = append(ev, "All measured signals are within this path's normal range")
	}
	return ev
}
