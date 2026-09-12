// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"strings"
	"testing"

	"netops/backend/internal/healthscore"
)

// Regression lock: list fields must serialize as [] never null — a nil slice →
// JSON null → the UI reads .length on null → white screen. Covers both branches.
func TestHealth_ListFieldsNeverNull(t *testing.T) {
	for _, name := range []string{"insufficient", "scored"} {
		var classes []healthscore.ClassResult
		if name == "scored" {
			classes = []healthscore.ClassResult{cls("availability", true, 0.0), cls("device_health", true, 0.1, contrib("device_health", "edge-1", 0.1))}
		} else {
			classes = []healthscore.ClassResult{cls("device_health", true, 0.3, contrib("device_health", "edge-1", 0.3))}
		}
		b, err := json.Marshal(healthscore.Aggregate("global", "", classes, "now"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{`"signal_classes_live":null`, `"stale_inputs":null`, `"contributions":null`} {
			if strings.Contains(string(b), f) {
				t.Errorf("[%s] response contains %s — would blank the UI; lists must be []", name, f)
			}
		}
	}
}

func cls(name string, live bool, badness float64, contribs ...healthscore.Contribution) healthscore.ClassResult {
	return healthscore.ClassResult{Class: name, Live: live, Badness: badness, Contribs: contribs}
}
func contrib(class, entity string, b float64) healthscore.Contribution {
	return healthscore.Contribution{SignalClass: class, Entity: entity, Badness: b, Reason: entity}
}

// Coverage honesty (§3): fewer than 2 live classes ⇒ INSUFFICIENT_TELEMETRY, no score.
func TestHealth_InsufficientWhenOneClass(t *testing.T) {
	r := healthscore.Aggregate("global", "", []healthscore.ClassResult{
		cls("device_health", true, 0.6, contrib("device_health", "edge-1", 0.6)),
		cls("availability", false, 0),
		cls("path_health", false, 0),
		cls("correlation", false, 0),
	}, "now")
	if r.CoverageStatus != "INSUFFICIENT_TELEMETRY" || r.Band != "insufficient_telemetry" {
		t.Fatalf("one class should be insufficient, got coverage=%s band=%s", r.CoverageStatus, r.Band)
	}
	if r.Score != nil {
		t.Errorf("insufficient telemetry must not return a score, got %v", *r.Score)
	}
}

// Owner's caution: probes ALONE must never produce a confident unhealthy verdict.
func TestHealth_ProbeOnlyIsInsufficientNotUnhealthy(t *testing.T) {
	r := healthscore.Aggregate("global", "", []healthscore.ClassResult{
		cls("path_health", true, 0.95, contrib("path_health", "dallas->cloud", 0.95)),
		cls("availability", false, 0),
		cls("device_health", false, 0),
		cls("correlation", false, 0),
	}, "now")
	if r.CoverageStatus != "INSUFFICIENT_TELEMETRY" {
		t.Fatalf("probe-only must be INSUFFICIENT_TELEMETRY (honest), got %s with score %v", r.CoverageStatus, r.Score)
	}
	if r.Score != nil {
		t.Errorf("probe-only must not assert a network-unhealthy score, got %v", *r.Score)
	}
}

func TestHealth_HealthyWhenMultipleLowClasses(t *testing.T) {
	r := healthscore.Aggregate("global", "", []healthscore.ClassResult{
		cls("availability", true, 0.0),
		cls("device_health", true, 0.05, contrib("device_health", "edge-1", 0.05)),
		cls("path_health", true, 0.1, contrib("path_health", "a->b", 0.1)),
	}, "now")
	if r.Score == nil || *r.Score < 80 || r.Band != "healthy" {
		t.Fatalf("low-badness multi-class should be healthy, got band=%s score=%v", r.Band, r.Score)
	}
	if r.Confidence != "medium" { // 3 live classes
		t.Errorf("3 live classes → medium confidence, got %s", r.Confidence)
	}
}

// Anti-averaging floor (§7): one severe class must not be averaged away by calm ones.
func TestHealth_HotspotNotAveragedAway(t *testing.T) {
	r := healthscore.Aggregate("global", "", []healthscore.ClassResult{
		cls("availability", true, 0.0),
		cls("device_health", true, 0.0),
		cls("correlation", true, 0.9, contrib("correlation", "WAN path loss", 0.9)),
	}, "now")
	if r.Score == nil || *r.Score > 30 {
		t.Fatalf("a severe class should pull the score down (floor), got %v", r.Score)
	}
	if r.Band != "critical" {
		t.Errorf("expected critical, got %s", r.Band)
	}
}

func TestHealth_StaleReducesConfidence(t *testing.T) {
	classes := []healthscore.ClassResult{
		cls("availability", true, 0.0),
		cls("device_health", true, 0.1, contrib("device_health", "edge-1", 0.1)),
		cls("path_health", true, 0.1, contrib("path_health", "a->b", 0.1)),
		cls("correlation", true, 0.1, contrib("correlation", "x", 0.1)),
	}
	fresh := healthscore.Aggregate("global", "", classes, "now")
	if fresh.Confidence != "high" { // 4 live
		t.Fatalf("4 live classes → high, got %s", fresh.Confidence)
	}
	classes[1].Stale = true
	staleR := healthscore.Aggregate("global", "", classes, "now")
	if staleR.Confidence == "high" {
		t.Errorf("stale input should reduce confidence below high, got %s", staleR.Confidence)
	}
	if len(staleR.StaleInputs) != 1 || staleR.StaleInputs[0] != "device_health" {
		t.Errorf("stale_inputs should list device_health, got %v", staleR.StaleInputs)
	}
}

// Explainability (§6): contributions present, sorted by points desc, summing ~deficit.
func TestHealth_ContributionsSortedAndSum(t *testing.T) {
	r := healthscore.Aggregate("global", "", []healthscore.ClassResult{
		cls("availability", true, 0.0),
		cls("device_health", true, 0.5, contrib("device_health", "edge-1", 0.5)),
		cls("correlation", true, 0.8, contrib("correlation", "WAN loss", 0.8)),
	}, "now")
	if r.Score == nil {
		t.Fatal("expected a score")
	}
	if len(r.Contributions) < 2 {
		t.Fatalf("expected contributions, got %d", len(r.Contributions))
	}
	for i := 1; i < len(r.Contributions); i++ {
		if r.Contributions[i].Points > r.Contributions[i-1].Points {
			t.Errorf("contributions must be sorted by points desc")
		}
	}
	// the higher-weighted, higher-badness correlation should lead
	if r.Contributions[0].SignalClass != "correlation" {
		t.Errorf("worst contributor should lead, got %s", r.Contributions[0].SignalClass)
	}
	sum := 0
	for _, c := range r.Contributions {
		sum += c.Points
	}
	deficit := 100 - *r.Score
	if sum < deficit-2 || sum > deficit+2 { // rounding tolerance
		t.Errorf("points should sum ~deficit %d, got %d", deficit, sum)
	}
}

func TestHealth_BandsAndHinge(t *testing.T) {
	for s, want := range map[int]string{95: "healthy", 70: "watch", 50: "degraded", 20: "critical"} {
		if got := healthscore.BandFromScore(s); got != want {
			t.Errorf("band(%d)=%s want %s", s, got, want)
		}
	}
	if healthscore.HingeN(0.6, 0.7, 0.95) != 0 {
		t.Error("below-lo hinge should be 0")
	}
	if healthscore.HingeN(0.99, 0.7, 0.95) != 1 {
		t.Error("above-hi hinge should be 1")
	}
}
