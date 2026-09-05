package dem

// score.go — the experience score. PURE: no clock, no network, no store. It
// takes measured window statistics and a declared budget and returns a verdict,
// so every branch (including every "not measured" branch) is unit-testable
// without a metrics backend.
//
// THE RULE THIS FILE EXISTS TO ENFORCE (§10, and the owner's standing
// instruction): a score is a CLAIM ABOUT MEASUREMENT. When nothing was
// measured there is no score — Measured=false plus a Reason naming why. A
// fabricated 0 reads as "totally broken" and a fabricated 100 reads as
// "verified healthy"; both are lies, and the second is the dangerous one.
//
// The three components and why they are weighted the way they are:
//
//	availability (0.55) — the operator's first question is "could people reach
//	    it at all". Scored as ERROR-BUDGET BURN, not as a raw percentage: 99.0%
//	    against a 99.9% budget is a tenfold budget overrun, and a raw-percentage
//	    score would render it as "99 out of 100" — reassuring and wrong.
//	latency (0.30) — scored against the target's DECLARED budget only. With no
//	    declared budget there is no threshold to be right or wrong about, so the
//	    component is reported as measured-but-unbudgeted and its weight is
//	    redistributed rather than being scored against an invented number.
//	path stability (0.15) — how often the observed forward path changed. Only
//	    the path-measuring kinds produce it; for the rest it is absent, never 0.
//
// A component that was not measured contributes NOTHING and its weight is
// redistributed over the components that were. If none were measured, the score
// is absent.

import (
	"math"
	"time"
)

// Component weights. They sum to 1 before renormalization.
const (
	WeightAvailability  = 0.55
	WeightLatency       = 0.30
	WeightPathStability = 0.15
)

// burnToZero is how far past its error budget a target must go before the
// availability component scores zero: 1 + burnToZero times the allowed miss
// ratio. 4 means "five times your error budget is a zero".
const burnToZero = 4.0

// latencyToZero is how far past its latency budget p95 must go before the
// latency component scores zero, as a multiple of the budget. 1.0 means "twice
// the budget is a zero".
const latencyToZero = 1.0

// Grade thresholds. Deliberately coarse — a score is a triage aid, not a
// measurement, and a two-decimal grade boundary would imply a precision the
// underlying sampling does not have.
const (
	GradeGood        = "good"
	GradeDegraded    = "degraded"
	GradePoor        = "poor"
	GradeNotMeasured = "not_measured"

	gradeGoodAt     = 90.0
	gradeDegradedAt = 75.0
)

// Reason codes for an absent score. They are STABLE identifiers the UI maps to
// copy; the human sentence rides alongside in Detail.
const (
	ReasonFeatureOff   = "feature_off"    // the DEM feature flag is off
	ReasonNoTargets    = "no_targets"     // the tenant has declared none
	ReasonPaused       = "paused"         // this target is paused by the operator
	ReasonNoProber     = "no_prober"      // no prober is reporting for this tenant
	ReasonNoSamples    = "no_samples"     // the window holds no probe samples
	ReasonQueryFailed  = "query_failed"   // the metrics backend did not answer
	ReasonWindowTooNew = "window_too_new" // the target was created inside the window
)

// WindowStats is what was actually measured for one Identity over one window.
// It is the ONLY input the maths reads, which is what makes every case here
// reachable from a table test.
//
// Counts are deliberately explicit rather than pre-divided ratios: "0 of 0" and
// "0 of 300" are different facts and the score must be able to tell them apart.
type WindowStats struct {
	Identity
	Window time.Duration

	// Samples / Successes are the availability numerator and denominator.
	Samples   int
	Successes int

	// Latency percentiles over the window, in milliseconds. LatencySamples==0
	// means latency was not measured (every check failed, or the kind reports
	// none) — distinct from "latency was 0 ms".
	LatencySamples int
	LatencyP50Ms   float64
	LatencyP95Ms   float64

	// PathSamples is the number of path observations; PathChanges is how many
	// of them differed from their predecessor. PathSamples<2 means path
	// stability was not measured — NOT that the path was stable.
	PathSamples int
	PathChanges int

	// LastProbe is the newest sample's timestamp. Zero when none.
	LastProbe time.Time
}

// Component is one scored dimension of the verdict.
type Component struct {
	// Measured is false when the dimension has no observation behind it. Every
	// other field is then meaningless and the UI must render the reason.
	Measured bool    `json:"measured"`
	Reason   string  `json:"reason,omitempty"`
	Value    float64 `json:"value,omitempty"`
	// Budget is the threshold this was scored against; BudgetDeclared says
	// whether the OPERATOR set it or a platform default was applied.
	Budget         float64 `json:"budget,omitempty"`
	BudgetDeclared bool    `json:"budget_declared"`
	// Met reports whether Value satisfies Budget.
	Met bool `json:"met"`
	// Points is the 0..100 contribution before weighting; Weight is the share
	// it actually carried after redistribution (0 when not measured).
	Points float64 `json:"points"`
	Weight float64 `json:"weight"`
	// Samples is the observation count behind Value — the honesty anchor: a
	// component computed from 3 samples is not the same claim as one from 300.
	Samples int `json:"samples"`
}

// Result is the experience verdict for one Identity over one window.
type Result struct {
	Identity
	Window string `json:"window"` // "1h" | "24h" — the requested label

	// Measured is the headline honesty flag. When false, Score is nil and
	// Reason/Detail say why; the UI must render that sentence, never a 0.
	Measured bool     `json:"measured"`
	Reason   string   `json:"reason,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Score    *float64 `json:"score,omitempty"`
	Grade    string   `json:"grade"`

	Availability  Component `json:"availability"`
	Latency       Component `json:"latency"`
	PathStability Component `json:"path_stability"`

	Samples   int        `json:"samples"`
	LastProbe *time.Time `json:"last_probe,omitempty"`
}

// NotMeasured builds an honest empty verdict. Every caller that cannot measure
// must go through here rather than returning a zero Result, so a "0" can only
// ever mean a real, measured zero.
func NotMeasured(id Identity, window, reason, detail string) Result {
	return Result{
		Identity: id, Window: window, Measured: false,
		Reason: reason, Detail: detail, Grade: GradeNotMeasured,
		Availability:  Component{Reason: reason},
		Latency:       Component{Reason: reason},
		PathStability: Component{Reason: reason},
	}
}

// Score computes the verdict for one target from its measured window.
//
// t supplies the budgets (and nothing else); w supplies the observations. The
// separation is what lets the alert rules, the API and the tests all agree on
// one definition of "over budget".
func Score(t Target, w WindowStats, window string) Result {
	id := w.Identity
	if id.Subject == "" {
		id = t.Identity()
	}
	if t.Paused {
		return NotMeasured(id, window, ReasonPaused,
			"this target is paused, so nothing was measured in this window")
	}
	if w.Samples <= 0 {
		return NotMeasured(id, window, ReasonNoSamples,
			"no probe result was recorded in this window — this is not a healthy result, it is an absent one")
	}

	res := Result{Identity: id, Window: window, Measured: true, Samples: w.Samples}
	if !w.LastProbe.IsZero() {
		lp := w.LastProbe.UTC()
		res.LastProbe = &lp
	}

	res.Availability = availabilityComponent(t, w)
	res.Latency = latencyComponent(t, w)
	res.PathStability = pathComponent(w)

	total, weight := 0.0, 0.0
	for _, c := range []Component{res.Availability, res.Latency, res.PathStability} {
		if !c.Measured {
			continue
		}
		total += c.Points * c.Weight
		weight += c.Weight
	}
	if weight <= 0 {
		// Samples existed but no dimension could be scored (a declared-budget
		// -less latency-only kind, say). Honest absence, not a zero.
		return NotMeasured(id, window, ReasonNoSamples,
			"probe results exist but none of them could be scored against a budget in this window")
	}
	// Redistribute: each measured component's weight becomes its share of the
	// weight that was actually available.
	score := round2(total / weight)
	res.Score = &score
	res.Grade = grade(score)
	res.Availability.Weight = shareOf(res.Availability, weight)
	res.Latency.Weight = shareOf(res.Latency, weight)
	res.PathStability.Weight = shareOf(res.PathStability, weight)
	return res
}

func shareOf(c Component, total float64) float64 {
	if !c.Measured || total <= 0 {
		return 0
	}
	return round2(c.Weight / total * 100)
}

// availabilityComponent scores the success ratio as error-budget burn.
func availabilityComponent(t Target, w WindowStats) Component {
	budget, declared := t.EffectiveAvailabilityBudget()
	avail := float64(w.Successes) / float64(w.Samples) * 100
	c := Component{
		Measured: true, Value: round2(avail), Budget: budget,
		BudgetDeclared: declared, Samples: w.Samples, Weight: WeightAvailability,
	}
	c.Met = avail+1e-9 >= budget
	c.Points = availabilityPoints(avail, budget)
	return c
}

// availabilityPoints maps a success ratio to 0..100 against its budget.
//
//	within budget          → 100
//	over budget            → linear down to 0 at (1+burnToZero)x the allowed
//	                         miss ratio
//	budget of exactly 100% → any miss at all is a zero (there is no error
//	                         budget to burn, which is what 100% means)
func availabilityPoints(avail, budget float64) float64 {
	if avail+1e-9 >= budget {
		return 100
	}
	allowedMiss := (100 - budget) / 100
	miss := (100 - avail) / 100
	if allowedMiss <= 0 {
		return 0
	}
	burn := miss / allowedMiss
	return clamp01(1-(burn-1)/burnToZero) * 100
}

// latencyComponent scores p95 against the declared latency budget. With no
// declared budget the latency is REPORTED but not scored: there is no
// threshold to be right or wrong about, and inventing one would turn a
// measurement into an opinion.
func latencyComponent(t Target, w WindowStats) Component {
	if w.LatencySamples <= 0 {
		return Component{
			Reason: ReasonNoSamples,
			// No successful check produced a timing. That is already counted
			// against availability; double-counting it here would punish one
			// failure twice.
		}
	}
	if t.LatencyBudgetMs <= 0 {
		return Component{
			Measured: false, Reason: "no_budget", Value: round2(w.LatencyP95Ms),
			Samples: w.LatencySamples, BudgetDeclared: false,
		}
	}
	c := Component{
		Measured: true, Value: round2(w.LatencyP95Ms), Budget: t.LatencyBudgetMs,
		BudgetDeclared: true, Samples: w.LatencySamples, Weight: WeightLatency,
	}
	c.Met = w.LatencyP95Ms <= t.LatencyBudgetMs+1e-9
	c.Points = latencyPoints(w.LatencyP95Ms, t.LatencyBudgetMs)
	return c
}

// latencyPoints: 100 within budget, linearly to 0 at (1+latencyToZero)x it.
func latencyPoints(p95, budget float64) float64 {
	if budget <= 0 {
		return 0
	}
	if p95 <= budget+1e-9 {
		return 100
	}
	over := p95/budget - 1
	return clamp01(1-over/latencyToZero) * 100
}

// pathComponent scores how often the observed forward path changed. Fewer than
// two path observations is NOT MEASURED — a single observation cannot show a
// change, and reporting it as "100% stable" would be a claim we did not earn.
func pathComponent(w WindowStats) Component {
	if w.PathSamples < 2 {
		return Component{Reason: "path_not_measured"}
	}
	transitions := w.PathSamples - 1
	changes := w.PathChanges
	if changes < 0 {
		changes = 0
	}
	if changes > transitions {
		changes = transitions
	}
	stable := float64(transitions-changes) / float64(transitions) * 100
	return Component{
		Measured: true, Value: round2(stable), Samples: w.PathSamples,
		Met: changes == 0, Points: stable, Weight: WeightPathStability,
	}
}

func grade(score float64) string {
	switch {
	case score >= gradeGoodAt:
		return GradeGood
	case score >= gradeDegradedAt:
		return GradeDegraded
	default:
		return GradePoor
	}
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func round2(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return math.Round(v*100) / 100
}

// Rollup aggregates per-target results into one site/app verdict.
//
// The aggregate is the WORST-weighted mean, not a plain mean: a site with nine
// healthy targets and one dead one is not 90% well, and a plain mean is how a
// single hard outage disappears into a green tile. Targets that were not
// measured are EXCLUDED from the mean and COUNTED separately, so the caller can
// say "6 of 8 scored, 2 not measured" instead of quietly scoring 6.
type Rollup struct {
	Key         string   `json:"key"`   // site or app label ("" = unlabelled)
	Scope       string   `json:"scope"` // "site" | "app"
	Window      string   `json:"window"`
	Measured    bool     `json:"measured"`
	Reason      string   `json:"reason,omitempty"`
	Score       *float64 `json:"score,omitempty"`
	Grade       string   `json:"grade"`
	Targets     int      `json:"targets"`
	Scored      int      `json:"scored"`
	NotMeasured int      `json:"not_measured"`
	Worst       *float64 `json:"worst_target_score,omitempty"`
}

// Aggregate folds results into one rollup. weightWorst is the share the single
// worst target carries; the rest is the mean of the scored targets.
const weightWorst = 0.4

func Aggregate(key, scope, window string, results []Result) Rollup {
	r := Rollup{Key: key, Scope: scope, Window: window, Targets: len(results), Grade: GradeNotMeasured}
	sum, n := 0.0, 0
	worst := math.Inf(1)
	for _, res := range results {
		if !res.Measured || res.Score == nil {
			r.NotMeasured++
			continue
		}
		sum += *res.Score
		n++
		if *res.Score < worst {
			worst = *res.Score
		}
	}
	r.Scored = n
	if n == 0 {
		r.Reason = ReasonNoSamples
		return r
	}
	mean := sum / float64(n)
	w := round2(worst)
	r.Worst = &w
	score := round2(mean*(1-weightWorst) + worst*weightWorst)
	r.Measured = true
	r.Score = &score
	r.Grade = grade(score)
	return r
}
