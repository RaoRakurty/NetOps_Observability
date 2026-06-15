package main

import (
	"strings"
	"testing"
)

// matureBaseline is a stable, high-confidence per-path baseline used as the
// fixture for the "behaving" scenarios (latency p50 35 / p99 90, jitter 4 / 28).
func matureBaseline() PathBaseline {
	return PathBaseline{
		Source:      baselinePath,
		Latency:     metricBaseline{P50: 35, P90: 55, P95: 61, P99: 90},
		Jitter:      metricBaseline{P50: 4, P90: 14, P95: 20, P99: 28},
		SampleCount: 18240,
		Days:        30,
		RouteStable: true,
	}
}

func confRank(c Confidence) int {
	for i, v := range confOrder {
		if v == c {
			return i
		}
	}
	return -1
}

func TestPathHealth_NormalPath(t *testing.T) {
	cur := PathCurrent{LatencyP95_5m: 40, JitterP95_5m: 5, LossPct5m: 0, HasLatency: true, HasJitter: true, HasLoss: true}
	h := ScorePathHealth(cur, matureBaseline(), weightsForClass(""))
	if h.State != healthHealthy {
		t.Fatalf("normal path: state=%s score=%.3f, want healthy", h.State, h.Score)
	}
	if h.Confidence != confHigh {
		t.Errorf("normal path: confidence=%s, want high", h.Confidence)
	}
	if h.FaultDomain != "insufficient_evidence" {
		t.Errorf("fault domain=%s, want insufficient_evidence (MVP)", h.FaultDomain)
	}
}

func TestPathHealth_DegradedPath(t *testing.T) {
	// latency near historical bad (88 vs p99 90) → floor pushes into Degraded.
	cur := PathCurrent{LatencyP95_5m: 88, JitterP95_5m: 20, LossPct5m: 0.5, HasLatency: true, HasJitter: true, HasLoss: true}
	h := ScorePathHealth(cur, matureBaseline(), weightsForClass(""))
	if h.State != healthDegraded {
		t.Fatalf("degraded path: state=%s score=%.3f, want degraded", h.State, h.Score)
	}
	if h.Severities["latency"] == nil || *h.Severities["latency"] < 0.75 {
		t.Errorf("expected high latency severity, got %v", h.Severities["latency"])
	}
}

func TestPathHealth_SeverePath(t *testing.T) {
	cur := PathCurrent{LatencyP95_5m: 145, JitterP95_5m: 40, LossPct5m: 3, HasLatency: true, HasJitter: true, HasLoss: true}
	h := ScorePathHealth(cur, matureBaseline(), weightsForClass(""))
	if h.State != healthSevere {
		t.Fatalf("severe path: state=%s score=%.3f, want severe (>1.0)", h.State, h.Score)
	}
	if h.Score <= 1.0 {
		t.Errorf("severe score=%.3f, want > 1.0", h.Score)
	}
}

func TestPathHealth_NewPathFallbackBaseline(t *testing.T) {
	// global cold-start baseline, almost no history → Low confidence, fallback wording.
	base := PathBaseline{
		Source:      baselineGlobal,
		Latency:     metricBaseline{P50: 50, P90: 180, P95: 240, P99: 300},
		Jitter:      metricBaseline{P50: 5, P90: 30, P95: 45, P99: 60},
		SampleCount: 12,
		Days:        0.2,
	}
	cur := PathCurrent{LatencyP95_5m: 120, JitterP95_5m: 10, LossPct5m: 0, HasLatency: true, HasJitter: true, HasLoss: true}
	h := ScorePathHealth(cur, base, weightsForClass(""))
	if h.Confidence != confLow {
		t.Errorf("new path: confidence=%s, want low", h.Confidence)
	}
	if h.BaselineSource != baselineGlobal {
		t.Errorf("baseline source=%s, want global", h.BaselineSource)
	}
	if !strings.Contains(h.Reason, "fallback") && !strings.Contains(h.Reason, "New path") {
		t.Errorf("new-path reason should mention fallback/new path, got %q", h.Reason)
	}
}

func TestPathHealth_LowSampleConfidence(t *testing.T) {
	b := matureBaseline()
	b.SampleCount = 50 // < 100 → Low regardless of day span
	if got := deriveConfidence(b); got != confLow {
		t.Errorf("low-sample confidence=%s, want low", got)
	}
}

func TestPathHealth_RouteChangeReducesConfidence(t *testing.T) {
	stable := matureBaseline()
	if got := deriveConfidence(stable); got != confHigh {
		t.Fatalf("stable baseline confidence=%s, want high", got)
	}
	changed := matureBaseline()
	changed.RouteStable = false
	changed.RouteChanged = true
	got := deriveConfidence(changed)
	if confRank(got) >= confRank(confHigh) {
		t.Errorf("route change should reduce confidence below high, got %s", got)
	}
}

func TestPathHealth_JitterOnlyDegradation(t *testing.T) {
	// latency normal, jitter near historical bad (27 vs p99 28), loss not measured.
	cur := PathCurrent{LatencyP95_5m: 38, JitterP95_5m: 27, HasLatency: true, HasJitter: true}
	h := ScorePathHealth(cur, matureBaseline(), weightsForClass(""))
	if h.State != healthDegraded && h.State != healthSevere {
		t.Fatalf("jitter-only: state=%s score=%.3f, want degraded+", h.State, h.Score)
	}
	if h.Severities["latency"] != nil && *h.Severities["latency"] >= 0.40 {
		t.Errorf("latency should be calm, got %v", h.Severities["latency"])
	}
	if h.Severities["loss"] != nil {
		t.Errorf("loss not measured → severity should be nil, got %v", *h.Severities["loss"])
	}
	if !strings.Contains(strings.ToLower(h.Reason), "jitter") {
		t.Errorf("reason should name jitter, got %q", h.Reason)
	}
}

func TestPathHealth_LossDominantDegradation(t *testing.T) {
	// only loss measured, 12% with burstiness → loss alone drives Degraded.
	cur := PathCurrent{LossPct5m: 12, LossBurst: 0.5, HasLoss: true}
	h := ScorePathHealth(cur, matureBaseline(), weightsForClass(""))
	if h.State != healthDegraded && h.State != healthSevere {
		t.Fatalf("loss-dominant: state=%s score=%.3f, want degraded+", h.State, h.Score)
	}
	if !strings.Contains(strings.ToLower(h.Reason), "packet loss") {
		t.Errorf("reason should name packet loss, got %q", h.Reason)
	}
	if h.Severities["latency"] != nil || h.Severities["jitter"] != nil {
		t.Errorf("unmeasured latency/jitter must be nil (not 0), got lat=%v jit=%v", h.Severities["latency"], h.Severities["jitter"])
	}
}

func TestSelectBaseline_Cascade(t *testing.T) {
	perPathSparse := PathBaseline{Source: baselinePath, SampleCount: 50, Days: 2} // NOT ready
	perPathReady := PathBaseline{Source: baselinePath, SampleCount: 600, Days: 2} // ready (≥500)
	classFallback := PathBaseline{Source: baselineClass}                          // always ready

	// sparse per-path → falls through to class fallback
	got, ok := SelectBaseline([]BaselineCandidate{{perPathSparse, true}, {classFallback, true}})
	if !ok || got.Source != baselineClass {
		t.Errorf("sparse per-path should fall back to class, got %s ok=%v", got.Source, ok)
	}
	// ready per-path → used directly
	got, ok = SelectBaseline([]BaselineCandidate{{perPathReady, true}, {classFallback, true}})
	if !ok || got.Source != baselinePath {
		t.Errorf("ready per-path should be selected, got %s ok=%v", got.Source, ok)
	}
	// 7-day readiness path
	got, ok = SelectBaseline([]BaselineCandidate{{PathBaseline{Source: baselinePath, SampleCount: 10, Days: 8}, true}, {classFallback, true}})
	if !ok || got.Source != baselinePath {
		t.Errorf("7-day per-path should be selected, got %s ok=%v", got.Source, ok)
	}
}

func TestBandFor(t *testing.T) {
	cases := []struct {
		s float64
		w HealthState
	}{{0.0, healthHealthy}, {0.39, healthHealthy}, {0.40, healthWatch}, {0.74, healthWatch}, {0.75, healthDegraded}, {1.0, healthDegraded}, {1.01, healthSevere}}
	for _, c := range cases {
		if got := bandFor(c.s); got != c.w {
			t.Errorf("bandFor(%.2f)=%s, want %s", c.s, got, c.w)
		}
	}
}
