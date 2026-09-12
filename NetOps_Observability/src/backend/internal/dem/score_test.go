// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dem

// score_test.go — the maths, and above all the NOT-MEASURED branches. The rule
// under test throughout: an absent measurement must produce an absent score,
// never a 0 (which renders as "totally broken") and never a 100 (which renders
// as "verified healthy").

import (
	"math"
	"testing"
	"time"
)

func budgeted(avail, latency float64) Target {
	return Target{
		TenantID: "acme", ID: "dem-1", Kind: KindHTTP, Name: "portal",
		Site: "dc1", App: "portal",
		AvailabilityBudgetPct: avail, LatencyBudgetMs: latency,
	}
}

func TestNoSamplesIsNotMeasuredNotZero(t *testing.T) {
	res := Score(budgeted(99, 200), WindowStats{}, Window1h)
	if res.Measured {
		t.Fatal("an empty window was reported as measured")
	}
	if res.Score != nil {
		t.Fatalf("an empty window produced a score of %v — absence is not a zero", *res.Score)
	}
	if res.Reason != ReasonNoSamples || res.Grade != GradeNotMeasured {
		t.Fatalf("reason/grade: %q %q", res.Reason, res.Grade)
	}
	if res.Detail == "" {
		t.Fatal("a not-measured verdict carries no sentence for the operator to read")
	}
}

func TestPausedTargetIsNotMeasured(t *testing.T) {
	tgt := budgeted(99, 200)
	tgt.Paused = true
	res := Score(tgt, WindowStats{Samples: 60, Successes: 60}, Window1h)
	if res.Measured || res.Reason != ReasonPaused {
		t.Fatalf("paused target scored: %+v", res)
	}
}

func TestPerfectWindowScoresFull(t *testing.T) {
	res := Score(budgeted(99, 200), WindowStats{
		Samples: 60, Successes: 60,
		LatencySamples: 60, LatencyP50Ms: 40, LatencyP95Ms: 90,
		PathSamples: 10, PathChanges: 0,
		LastProbe: time.Unix(1_757_000_000, 0),
	}, Window1h)
	if !res.Measured || res.Score == nil || *res.Score != 100 {
		t.Fatalf("clean window did not score 100: %+v", res)
	}
	if res.Grade != GradeGood {
		t.Fatalf("grade %q", res.Grade)
	}
	if res.LastProbe == nil {
		t.Fatal("last probe was dropped")
	}
	for _, c := range []Component{res.Availability, res.Latency, res.PathStability} {
		if !c.Measured || !c.Met {
			t.Fatalf("component not measured/met: %+v", c)
		}
	}
}

// Availability is scored as ERROR-BUDGET BURN. 99.0% against a 99.9% budget is a
// tenfold overrun and must NOT read as "99 out of 100".
func TestAvailabilityIsErrorBudgetBurnNotRawPercent(t *testing.T) {
	pts := availabilityPoints(99.0, 99.9)
	if pts > 1 {
		t.Fatalf("a 10x error-budget overrun scored %.2f points — a raw-percentage score would flatter it", pts)
	}
	if got := availabilityPoints(99.95, 99.9); got != 100 {
		t.Fatalf("within budget scored %.2f", got)
	}
	// Exactly at the budget is within it.
	if got := availabilityPoints(99.9, 99.9); got != 100 {
		t.Fatalf("exactly at budget scored %.2f", got)
	}
	// A 100% budget has no error budget at all: any miss is a zero.
	if got := availabilityPoints(99.99, 100); got != 0 {
		t.Fatalf("a miss against a 100%% budget scored %.2f", got)
	}
	if got := availabilityPoints(100, 100); got != 100 {
		t.Fatalf("a clean window against a 100%% budget scored %.2f", got)
	}
	// Monotonic: worse availability never scores better.
	prev := math.Inf(1)
	for a := 100.0; a >= 90; a -= 0.5 {
		got := availabilityPoints(a, 99)
		if got > prev+1e-9 {
			t.Fatalf("non-monotonic at %.1f%%: %.2f > %.2f", a, got, prev)
		}
		prev = got
	}
}

func TestLatencyPoints(t *testing.T) {
	if got := latencyPoints(100, 200); got != 100 {
		t.Fatalf("within budget scored %.2f", got)
	}
	if got := latencyPoints(300, 200); got <= 0 || got >= 100 {
		t.Fatalf("50%% over budget scored %.2f (want a partial credit)", got)
	}
	if got := latencyPoints(400, 200); got != 0 {
		t.Fatalf("twice the budget scored %.2f", got)
	}
}

// With no DECLARED latency budget there is no threshold to be right about, so
// latency is reported but NOT scored — and its weight is redistributed rather
// than being scored against an invented number.
func TestUnbudgetedLatencyIsReportedNotScored(t *testing.T) {
	tgt := budgeted(99, 0)
	res := Score(tgt, WindowStats{
		Samples: 60, Successes: 60, LatencySamples: 60, LatencyP95Ms: 900,
	}, Window1h)
	if res.Latency.Measured {
		t.Fatal("latency was scored against a budget nobody declared")
	}
	if res.Latency.Value != 900 || res.Latency.Reason != "no_budget" {
		t.Fatalf("latency not reported honestly: %+v", res.Latency)
	}
	if res.Score == nil || *res.Score != 100 {
		t.Fatalf("weight was not redistributed onto the measured components: %+v", res.Score)
	}
	if res.Availability.Weight != 100 {
		t.Fatalf("availability should carry the whole weight, got %.2f", res.Availability.Weight)
	}
}

// Fewer than two path observations cannot show a change. Reporting that as
// "100% stable" would be a claim we did not earn.
func TestPathStabilityNeedsTwoObservations(t *testing.T) {
	for _, n := range []int{0, 1} {
		c := pathComponent(WindowStats{PathSamples: n})
		if c.Measured {
			t.Fatalf("%d path observations were scored", n)
		}
		if c.Reason != "path_not_measured" {
			t.Fatalf("reason %q", c.Reason)
		}
	}
	c := pathComponent(WindowStats{PathSamples: 5, PathChanges: 2})
	if !c.Measured || c.Met {
		t.Fatalf("a changing path: %+v", c)
	}
	if c.Value != 50 {
		t.Fatalf("2 changes over 4 transitions is 50%% stable, got %.2f", c.Value)
	}
}

// A failed check has no latency. Latency samples of 0 must not be double-counted
// as a latency failure on top of the availability failure.
func TestNoLatencySamplesDoesNotPunishTwice(t *testing.T) {
	res := Score(budgeted(99, 200), WindowStats{Samples: 60, Successes: 0}, Window1h)
	if res.Latency.Measured {
		t.Fatal("latency was scored with no timing behind it")
	}
	if res.Score == nil || *res.Score != 0 {
		t.Fatalf("a totally-down window should score 0 on availability alone: %+v", res.Score)
	}
	if res.Grade != GradePoor {
		t.Fatalf("grade %q", res.Grade)
	}
}

func TestSuccessesAreCappedBySamples(t *testing.T) {
	c := availabilityComponent(budgeted(99, 0), WindowStats{Samples: 10, Successes: 10})
	if c.Value != 100 {
		t.Fatalf("availability %.2f", c.Value)
	}
}

// The rollup must not let one hard outage disappear into a green tile, and it
// must count what it could not score instead of quietly dropping it.
func TestAggregateWeightsTheWorstAndCountsTheUnmeasured(t *testing.T) {
	good := func(v float64) Result {
		s := v
		return Result{Measured: true, Score: &s}
	}
	list := []Result{good(100), good(100), good(100), good(100), good(100),
		good(100), good(100), good(100), good(100), good(0)}
	roll := Aggregate("dc1", "site", Window1h, list)
	if !roll.Measured || roll.Score == nil {
		t.Fatalf("rollup: %+v", roll)
	}
	if *roll.Score >= 90 {
		t.Fatalf("one dead target out of ten scored %.2f — a plain mean is how an outage hides", *roll.Score)
	}
	if roll.Worst == nil || *roll.Worst != 0 {
		t.Fatalf("worst not reported: %+v", roll.Worst)
	}

	mixed := []Result{good(100), NotMeasured(Identity{}, Window1h, ReasonNoSamples, "x")}
	roll = Aggregate("dc1", "site", Window1h, mixed)
	if roll.Scored != 1 || roll.NotMeasured != 1 || roll.Targets != 2 {
		t.Fatalf("counts: %+v", roll)
	}
	if *roll.Score != 100 {
		t.Fatalf("an unmeasured target dragged the mean: %.2f", *roll.Score)
	}

	none := Aggregate("dc1", "site", Window1h, []Result{
		NotMeasured(Identity{}, Window1h, ReasonNoSamples, "x")})
	if none.Measured || none.Score != nil || none.Grade != GradeNotMeasured {
		t.Fatalf("an all-unmeasured group produced a score: %+v", none)
	}
}

func TestNotMeasuredCarriesReasonOnEveryComponent(t *testing.T) {
	res := NotMeasured(Identity{Tenant: "acme", Subject: "dem-1"}, Window24h, ReasonFeatureOff, "the feature is off")
	for _, c := range []Component{res.Availability, res.Latency, res.PathStability} {
		if c.Measured || c.Reason != ReasonFeatureOff {
			t.Fatalf("component: %+v", c)
		}
	}
	if res.Score != nil || res.Grade != GradeNotMeasured {
		t.Fatalf("%+v", res)
	}
}
