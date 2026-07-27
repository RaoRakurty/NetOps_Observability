package main

// path_health_unknown_test.go — SILENT-CRITICAL-2 from the 2026-07-27 audit.
//
// When every signal query failed, `den` stayed 0, so `score` stayed 0.0, and
// bandFor(0) is "healthy" — then the evidence builder appended the sentence
// "All measured signals are within this path's normal range". An operator
// sorting worst-first during a WAN incident saw a wall of green and concluded
// the paths were fine, when in fact nothing had been measured at all.
//
// This is the NORMAL partial-failure shape rather than an edge case: the heavy
// [5m] quantile queries are the first to time out under VictoriaMetrics load
// while the cheap ones still answer.

import (
	"strings"
	"testing"
)

// The control and the fix in one place: measured signals still band normally,
// and no measurable signal is UNKNOWN — never healthy.
func TestUnmeasuredPathIsUnknownNotHealthy(t *testing.T) {
	if bandFor(0) != healthHealthy {
		t.Fatalf("control: bandFor(0) should still be %q — the fix is at the "+
			"call site (den==0), not in the banding", healthHealthy)
	}
	if healthUnknown == healthHealthy {
		t.Fatal("unknown must be a distinct state from healthy")
	}
}

// The affirmative sentence is the actual harm: a claim about the NETWORK
// manufactured from a failure to measure it.
func TestUnknownPathNeverClaimsSignalsAreNormal(t *testing.T) {
	ev := buildEvidence(PathCurrent{}, PathBaseline{}, map[string]float64{}, healthUnknown)
	joined := strings.Join(ev, " | ")
	if strings.Contains(joined, "within this path's normal range") {
		t.Errorf("an unmeasured path claimed its signals are normal: %q", joined)
	}
	if !strings.Contains(strings.ToLower(joined), "unknown") {
		t.Errorf("an unmeasured path must say so plainly, got %q", joined)
	}

	// Control: a genuinely healthy path still gets its affirmative sentence, so
	// the fix cannot degenerate into "never state anything".
	ok := strings.Join(buildEvidence(PathCurrent{}, PathBaseline{}, map[string]float64{}, healthHealthy), " | ")
	if !strings.Contains(ok, "within this path's normal range") {
		t.Errorf("a measured healthy path lost its evidence line: %q", ok)
	}
}
