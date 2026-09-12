// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package healthscore is the scope health-score aggregation core (Phase-2
// W3.4, extracted from package main's health_score.go): signal-class weights,
// the weighted blend with the anti-averaging floor, coverage honesty, deficit
// distribution, hinge curves and the health bands (including the
// unknown-not-healthy rule). Pure — the four signal-class fetchers and the
// handler stay in main (they hold the VM/CH transports and the request).
package healthscore

import (
	"math"
	"sort"
	"strconv"

	"netops/backend/pathgraph"
)

var ClassWeights = map[string]float64{
	"availability":  3.0,
	"path_health":   2.5,
	"correlation":   2.0,
	"device_health": 1.5,
	"flow_health":   1.5, // #69 P2 service scope: passive attributed-volume evidence (svc_health.go)
}

type Contribution struct {
	SignalClass string  `json:"signal_class"`
	Entity      string  `json:"entity"`
	Badness     float64 `json:"badness"`
	Points      int     `json:"points"`
	Reason      string  `json:"reason"`
	Timestamp   string  `json:"timestamp,omitempty"`
}

// ClassResult is one signal class's verdict for the scope. Live=false means
// the class had no data (or its source was unreachable) — excluded from coverage.
type ClassResult struct {
	Class    string
	Live     bool
	Stale    bool
	Badness  float64 // class-level badness (worst meaningful within the class), 0..2
	Contribs []Contribution
}

type Resp struct {
	Scope             string         `json:"scope"`
	ID                string         `json:"id,omitempty"`
	Score             *int           `json:"score"` // null when insufficient telemetry
	Band              string         `json:"band"`
	Confidence        string         `json:"confidence"`
	CoverageStatus    string         `json:"coverage_status"`
	SignalClassesLive []string       `json:"signal_classes_live"`
	Contributions     []Contribution `json:"contributions"`
	StaleInputs       []string       `json:"stale_inputs"`
	UpdatedAt         string         `json:"updated_at"`
}

func BandFromScore(s int) string {
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

func ReduceConfStr(c string) string {
	switch c {
	case "high":
		return "medium"
	case "medium":
		return "medium_low"
	default:
		return "low"
	}
}

// HingeN: 0 below lo, linear lo→hi, 1 above hi. Used for utilization/CPU/mem where
// a signal is only "bad" near saturation.
func HingeN(v, lo, hi float64) float64 {
	if v <= lo {
		return 0
	}
	if v >= hi {
		return 1
	}
	return (v - lo) / (hi - lo)
}

// Aggregate is the PURE core (unit-tested): coverage honesty, weighted
// blend with the anti-averaging floor (so a hotspot isn't averaged away), bands,
// confidence, and per-contribution points that sum to the score deficit.
func Aggregate(scope, id string, classes []ClassResult, nowISO string) Resp {
	// Init to empty (never nil): a nil slice serializes to JSON null, and the UI
	// reads .length on these — null would throw and blank the page. API contract:
	// list fields are always arrays.
	live := []ClassResult{}
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
		return Resp{
			Scope: scope, ID: id, Score: nil, Band: "insufficient_telemetry",
			Confidence: "low", CoverageStatus: "INSUFFICIENT_TELEMETRY",
			SignalClassesLive: liveNames, Contributions: []Contribution{},
			StaleInputs: stale, UpdatedAt: nowISO,
		}
	}

	var num, den, maxB float64
	for _, c := range live {
		w := ClassWeights[c.Class]
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
	blend = pathgraph.ClampF(blend, 0, 1)
	score := int(math.Round(100 * (1 - blend)))
	deficit := 100 - score

	// distribute the deficit across contributions by weighted badness
	var wsum float64
	for _, c := range live {
		w := ClassWeights[c.Class]
		for _, ct := range c.Contribs {
			wsum += w * ct.Badness
		}
	}
	contribs := []Contribution{}
	for _, c := range live {
		w := ClassWeights[c.Class]
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
		conf = ReduceConfStr(conf)
	}

	return Resp{
		Scope: scope, ID: id, Score: &score, Band: BandFromScore(score),
		Confidence: conf, CoverageStatus: "OK", SignalClassesLive: liveNames,
		Contributions: contribs, StaleInputs: stale, UpdatedAt: nowISO,
	}
}

// ── handler ──────────────────────────────────────────────────────────────────

func Pct0(v float64) string {
	return strconv.FormatFloat(v, 'f', 0, 64) + "%"
}
func Pct1(v float64) string { // v is a 0..1 fraction
	return strconv.FormatFloat(v*100, 'f', 1, 64) + "%"
}
func Round2s(v float64) string { return strconv.FormatFloat(math.Round(v*100)/100, 'f', -1, 64) }
