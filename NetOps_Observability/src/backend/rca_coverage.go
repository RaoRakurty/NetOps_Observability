package main

// rca_coverage.go — the EvidenceCoverageEngine (Phase C).
//
// ONE place derives evidence-coverage quality per evidence class, from real
// per-lane observations + the incident window, with explicit per-class semantics
// — so no page of a report can call a lane "Full/Normal" that did not actually
// span the incident, and a one-shot control-plane transition is never judged by
// continuous-coverage rules (the P-027379 root defects, audit §2).
//
// The engine consumes only stored records + injected policy; it never invents a
// number. Where a dimension is genuinely underivable (no stored cadence, no
// stored collector health) it reports `unknown` — it does NOT default-fabricate
// a healthy answer (owner constraint 5). Renderers (Phase D) and the quality gate
// (Phase E) consume the CoverageAssessment; the legacy `buildEvidenceCoverage` /
// `rcaLaneWindowCoverage` shims (rca_report_wording.go) now derive from THIS
// engine, keeping their signatures stable for the Phase D renderer swap.
//
// Owner constraints this file enforces (rca-evidence-accounting-plan.md):
//   - Constraint 5: coverage = expected cadence + actual covered intervals
//     INCLUDING internal gaps — never first/last timestamps alone. Cadence is
//     derived from the observed inter-arrival distribution and/or the prober
//     schedule config, and marked `unknown` where genuinely underivable.
//   - Constraint 6: per-class strategies — continuous, event-based (routing /
//     tunnel STATE TRANSITIONS = point_in_time, never continuous rules),
//     freshness-based, and batch.
//   - Constraint 7: "Normal" requires ALL of temporal sufficiency, scope
//     relevance, collector health, and the source's ability to observe the
//     claimed condition. "No anomaly linked to case" alone is NEVER "Normal".
//   - Constraints 4/9: legacy lanes with no stored cadence/health render clearly
//     as `unknown`/partial — never a fabricated "Full/Normal".

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// evidenceStrategy is the coverage-evaluation strategy for an evidence class. The
// strategy — NOT the raw modality name — decides which coverage rules apply.
type evidenceStrategy string

const (
	// strategyContinuous — a lane expected to sample regularly across the whole
	// incident window (device telemetry, passive flow, active probes). Judged by
	// covered-interval ratio + leading/trailing/internal gaps against expected
	// cadence.
	strategyContinuous evidenceStrategy = "continuous"
	// strategyEventBased — a lane that reports discrete STATE TRANSITIONS (routing
	// adjacency, tunnel up/down, control-plane events). A transition is a
	// point_in_time fact; it is NEVER judged by continuous-coverage rules — a 19s
	// control-plane event is not "78% covered", it is a single observed transition.
	strategyEventBased evidenceStrategy = "event_based"
	// strategyFreshness — a lane whose evidence is a last-known snapshot (inventory,
	// controller last-seen, config). Judged by the AGE of the latest observation
	// against a staleness threshold, not by window span.
	strategyFreshness evidenceStrategy = "freshness"
	// strategyBatch — a lane delivered in periodic batches (scheduled report,
	// rollup). Judged by whether a batch covering the window arrived within the
	// expected batch interval.
	strategyBatch evidenceStrategy = "batch"
)

// coverageQuality is the closed set of coverage-quality states (spec). Anything not
// positively derivable is `unknown` — never silently upgraded.
type coverageQuality string

const (
	qualityComplete      coverageQuality = "complete"       // spanned the window at expected cadence, no material gap
	qualitySubstantial   coverageQuality = "substantial"    // ≥ substantial threshold but short of complete
	qualityPartial       coverageQuality = "partial"        // ≥ minimal threshold but short of substantial
	qualityMinimal       coverageQuality = "minimal"        // observed, but below the minimal threshold
	qualityPointInTime   coverageQuality = "point_in_time"  // event-based: a discrete transition, not a span
	qualityStale         coverageQuality = "stale"          // freshness/batch: last observation is too old
	qualityIrrelevant    coverageQuality = "irrelevant"     // out of the incident's scope
	qualityUnavailable   coverageQuality = "unavailable"    // configured to observe here, but nothing arrived
	qualityNotConfigured coverageQuality = "not_configured" // no source configured for this class
	qualityUnknown       coverageQuality = "unknown"        // cannot be established from stored records
)

// coverageTri is a fail-open-only tri-state: yes | no | unknown. Only the KNOWN
// negative (`no`) vetoes a Normal claim; `unknown` never fabricates a positive.
type coverageTri string

const (
	triUnknown coverageTri = "unknown"
	triYes     coverageTri = "yes"
	triNo      coverageTri = "no"
)

// collectorHealth is the health of the collector behind a lane. `unknown` is the
// honest legacy state (no per-lane health history is stored — audit §4); only a
// KNOWN `degraded` vetoes Normal.
type collectorHealth string

const (
	collectorUnknownHealth collectorHealth = "unknown"
	collectorHealthy       collectorHealth = "healthy"
	collectorDegraded      collectorHealth = "degraded"
)

// cadenceSource records HOW the expected cadence was derived, so the report can be
// honest about provenance (schedule config vs inferred vs unknown).
type cadenceSource string

const (
	cadenceUnknown      cadenceSource = "unknown"
	cadenceFromSchedule cadenceSource = "schedule"
	cadenceFromArrivals cadenceSource = "inter_arrival"
)

// gapInterval is one uncovered interval inside the incident window.
type gapInterval struct {
	Start string `json:"start"`
	End   string `json:"end"`
	Dur   string `json:"duration"`
}

// LaneCoverageInput is everything the engine needs to assess ONE lane. Built from
// stored records only; absent fields stay at their zero value and surface as
// `unknown` in the assessment — never fabricated.
type LaneCoverageInput struct {
	Class       string    // engine modality key (device_telemetry, control_plane, …)
	WindowStart time.Time // incident window start (first anomalous observation)
	WindowEnd   time.Time // incident window end (last anomalous observation)
	Now         time.Time // reference "now" for freshness (zero → freshness unknown)

	// Observations is the FULL per-observation timestamp series for this lane in the
	// window slice (rich path — enables internal-gap + inter-arrival cadence). When
	// nil, the engine falls back to LaneStart/LaneEnd (the legacy min/max-only path)
	// and reports cadence + internal gaps as `unknown`.
	Observations []time.Time
	LaneStart    time.Time // min observation ts (fallback when Observations is nil)
	LaneEnd      time.Time // max observation ts (fallback when Observations is nil)

	TotalCount     int // all observations in this lane in the window
	AnomalousCount int // case-linked anomalous observations in this lane

	// ScheduleInterval is the configured cadence for this lane (prober schedule
	// registry). Zero = not known → cadence is derived from inter-arrivals or stays
	// unknown. NEVER fabricated from first/last alone (constraint 5).
	ScheduleInterval time.Duration

	// Dimensions the engine consumes when known; `unknown`/zero when not stored.
	Scope              coverageTri     // is this lane in the incident's scope?
	CollectorHealthIn  collectorHealth // collector health for this lane
	Sampled            coverageTri     // is the lane sampled (e.g. sFlow 1:N)?
	BaselinePresent    coverageTri     // is a baseline available for this lane?
	ObserverCanObserve coverageTri     // can this source observe the claimed condition?
}

// CoverageAssessment is the canonical per-lane coverage verdict. Renderers and the
// quality gate consume it; it is the single source of coverage truth for a lane.
type CoverageAssessment struct {
	Class    string           `json:"class"`
	Strategy evidenceStrategy `json:"strategy"`
	Quality  coverageQuality  `json:"quality"`

	// Temporal accounting (constraint 5).
	OverlapStart     string        `json:"overlap_start,omitempty"`
	OverlapEnd       string        `json:"overlap_end,omitempty"`
	CoverageRatio    float64       `json:"coverage_ratio"` // 0..1; meaningful only when RatioKnown
	RatioKnown       bool          `json:"ratio_known"`
	LeadingGap       string        `json:"leading_gap,omitempty"`
	TrailingGap      string        `json:"trailing_gap,omitempty"`
	InternalGaps     []gapInterval `json:"internal_gaps,omitempty"`
	InternalGapTotal string        `json:"internal_gap_total,omitempty"`
	MissingInterval  string        `json:"missing_interval,omitempty"` // human summary (legacy field feed)

	// Cadence provenance (constraint 5).
	ExpectedCadence string        `json:"expected_cadence,omitempty"`
	CadenceKnown    bool          `json:"cadence_known"`
	CadenceSource   cadenceSource `json:"cadence_source"`

	// Freshness (freshness/batch strategies; unknown otherwise).
	Freshness      string `json:"freshness,omitempty"`
	FreshnessKnown bool   `json:"freshness_known"`

	// Qualitative dimensions, carried through honestly (unknown when not stored).
	Scope              coverageTri     `json:"scope_relevance"`
	CollectorHealth    collectorHealth `json:"collector_health"`
	Sampled            coverageTri     `json:"sampled"`
	BaselinePresent    coverageTri     `json:"baseline_present"`
	ObserverCanObserve coverageTri     `json:"observer_can_observe"`

	// Eligibility (every assessment yields all three + reason codes).
	ConfidenceEligible bool     `json:"confidence_eligible"`
	ImpactEligible     bool     `json:"impact_eligible"`
	NormalityEligible  bool     `json:"normality_eligible"`
	ConfidenceReasons  []string `json:"confidence_reasons,omitempty"`
	ImpactReasons      []string `json:"impact_reasons,omitempty"`
	NormalityReasons   []string `json:"normality_reasons,omitempty"`
}

// coverageThresholds are the ratio cut-points (as fractions) between quality states
// for one evidence class. Defaults 95/80/25 (owner constraint 6 / spec).
type coverageThresholds struct {
	Complete    float64       // ≥ this → complete (default 0.95)
	Substantial float64       // ≥ this → substantial (default 0.80)
	Minimal     float64       // ≥ this → partial; below → minimal (default 0.25)
	StaleAfter  time.Duration // freshness/batch: older than this → stale (default 15m)
}

func defaultCoverageThresholds() coverageThresholds {
	return coverageThresholds{Complete: 0.95, Substantial: 0.80, Minimal: 0.25, StaleAfter: 15 * time.Minute}
}

// tenantCoveragePolicy is one tenant's structured coverage policy (the CANONICAL
// source; UI editor deferred). Per-class threshold + strategy overrides. A tenant
// only ever sees its OWN policy — the engine never reads another tenant's map.
type tenantCoveragePolicy struct {
	// Thresholds by evidence class ("device_telemetry" → …); "*" is the tenant-wide
	// default. Absent → the global default thresholds.
	Thresholds map[string]coverageThresholds
	// Strategy overrides by evidence class (rare; structural defaults suffice).
	Strategy map[string]evidenceStrategy
}

// coveragePolicy holds global defaults + per-tenant overrides. Built once at
// construction and never mutated (safe for concurrent reads).
type coveragePolicy struct {
	globalThresholds map[string]coverageThresholds // by class; "*" default
	perTenant        map[string]tenantCoveragePolicy
	strategyByClass  map[string]evidenceStrategy // structural + env defaults
}

// EvidenceCoverageEngine assesses lane coverage per the injected policy. The
// package-level instance (rcaCoverageEngine) is used by the report shims; tests
// construct their own with explicit per-tenant policy.
type EvidenceCoverageEngine struct {
	policy coveragePolicy
}

// rcaCoverageEngine is the package-level coverage engine used by the report shims,
// built with env/config defaults (per-tenant structured policy injected later, same
// deferred-UI pattern as the observer classification registry).
var rcaCoverageEngine = newCoverageEngine(nil)

// defaultStrategyByClass maps our known lanes to a coverage strategy. Control-plane
// / management-plane lanes are event-based (state transitions) — the single most
// important correction from the audit. Everything else defaults continuous.
var defaultStrategyByClass = map[string]evidenceStrategy{
	"device_telemetry": strategyContinuous,
	"passive_flow":     strategyContinuous,
	"active_probe":     strategyContinuous,
	"control_plane":    strategyEventBased,
	"management_plane": strategyEventBased,
	// RCA spec item 8: verification runs are on-demand check batteries —
	// event-based by nature, never a continuous lane with expected cadence.
	"active_verification": strategyEventBased,
}

// newCoverageEngine builds the engine. `perTenant` is the canonical per-tenant
// policy (may be nil). Global threshold + strategy defaults come from env:
//
//	CORR_COVERAGE_THRESHOLDS   "class:complete/substantial/minimal" (percent), comma-sep
//	CORR_COVERAGE_STALE_AFTER  a Go duration (freshness/batch staleness), applies to "*"
//	CORR_COVERAGE_STRATEGY     "class:strategy" comma-sep (rare override)
//
// Env supplies DEFAULTS only; per-tenant structured policy is canonical (owner
// decision 2). Unparseable entries are ignored (fail to the safe default).
func newCoverageEngine(perTenant map[string]tenantCoveragePolicy) *EvidenceCoverageEngine {
	pol := coveragePolicy{
		globalThresholds: map[string]coverageThresholds{"*": defaultCoverageThresholds()},
		perTenant:        map[string]tenantCoveragePolicy{},
		strategyByClass:  map[string]evidenceStrategy{},
	}
	for k, v := range defaultStrategyByClass {
		pol.strategyByClass[k] = v
	}
	// env: stale-after (applies to the "*" default thresholds).
	if d := envDuration("CORR_COVERAGE_STALE_AFTER", 0); d > 0 {
		def := pol.globalThresholds["*"]
		def.StaleAfter = d
		pol.globalThresholds["*"] = def
	}
	// env: per-class thresholds.
	for _, entry := range splitEnvList(os.Getenv("CORR_COVERAGE_THRESHOLDS")) {
		class, spec, ok := strings.Cut(entry, ":")
		if !ok {
			continue
		}
		th, ok := parseThresholdSpec(spec, pol.globalThresholds["*"])
		if !ok {
			continue
		}
		pol.globalThresholds[strings.TrimSpace(class)] = th
	}
	// env: per-class strategy override.
	for _, entry := range splitEnvList(os.Getenv("CORR_COVERAGE_STRATEGY")) {
		class, strategy, ok := strings.Cut(entry, ":")
		if !ok {
			continue
		}
		if s, valid := parseStrategy(strategy); valid {
			pol.strategyByClass[strings.TrimSpace(class)] = s
		}
	}
	// per-tenant canonical policy (deep-copied so the caller can't mutate us).
	for t, tp := range perTenant {
		cp := tenantCoveragePolicy{
			Thresholds: map[string]coverageThresholds{},
			Strategy:   map[string]evidenceStrategy{},
		}
		for c, th := range tp.Thresholds {
			cp.Thresholds[c] = th
		}
		for c, s := range tp.Strategy {
			cp.Strategy[c] = s
		}
		pol.perTenant[t] = cp
	}
	return &EvidenceCoverageEngine{policy: pol}
}

// parseThresholdSpec parses "complete/substantial/minimal" as percentages (e.g.
// "95/80/25") into fractional thresholds, inheriting StaleAfter from base.
func parseThresholdSpec(spec string, base coverageThresholds) (coverageThresholds, bool) {
	parts := strings.Split(spec, "/")
	if len(parts) != 3 {
		return base, false
	}
	out := base
	dst := []*float64{&out.Complete, &out.Substantial, &out.Minimal}
	for i, p := range parts {
		// F-21: `f < 0 || f > 100` does NOT reject a NaN — every comparison with
		// NaN is false, so "NaN/80/25" slipped through the range check here and
		// was only caught by luck downstream (the ordering test also compares
		// false). Reject non-finite explicitly rather than by accident.
		f, ok := parseMetricFloat(p)
		if !ok || f < 0 || f > 100 {
			return base, false
		}
		*dst[i] = f / 100.0
	}
	if !(out.Complete >= out.Substantial && out.Substantial >= out.Minimal) {
		return base, false
	}
	return out, true
}

func parseStrategy(s string) (evidenceStrategy, bool) {
	switch evidenceStrategy(strings.ToLower(strings.TrimSpace(s))) {
	case strategyContinuous:
		return strategyContinuous, true
	case strategyEventBased:
		return strategyEventBased, true
	case strategyFreshness:
		return strategyFreshness, true
	case strategyBatch:
		return strategyBatch, true
	}
	return strategyContinuous, false
}

// strategyFor resolves the coverage strategy for (tenant, class): per-tenant
// override → structural/env default → continuous.
func (e *EvidenceCoverageEngine) strategyFor(tenant, class string) evidenceStrategy {
	if tp, ok := e.policy.perTenant[tenant]; ok {
		if s, ok := tp.Strategy[class]; ok {
			return s
		}
	}
	if s, ok := e.policy.strategyByClass[class]; ok {
		return s
	}
	return strategyContinuous
}

// thresholdsFor resolves the thresholds for (tenant, class), consulting ONLY the
// caller tenant's policy (isolation): per-tenant class → per-tenant "*" → global
// class → global "*". A tenant's override can never affect another tenant.
func (e *EvidenceCoverageEngine) thresholdsFor(tenant, class string) coverageThresholds {
	if tp, ok := e.policy.perTenant[tenant]; ok {
		if th, ok := tp.Thresholds[class]; ok {
			return th
		}
		if th, ok := tp.Thresholds["*"]; ok {
			return th
		}
	}
	if th, ok := e.policy.globalThresholds[class]; ok {
		return th
	}
	return e.policy.globalThresholds["*"]
}

// Assess produces the CoverageAssessment for one lane and tenant. Pure function of
// the input + the caller tenant's policy — no shared mutable state.
func (e *EvidenceCoverageEngine) Assess(tenant string, in LaneCoverageInput) CoverageAssessment {
	strategy := e.strategyFor(tenant, in.Class)
	th := e.thresholdsFor(tenant, in.Class)
	a := CoverageAssessment{
		Class:              in.Class,
		Strategy:           strategy,
		Scope:              orTri(in.Scope),
		CollectorHealth:    orHealth(in.CollectorHealthIn),
		Sampled:            orTri(in.Sampled),
		BaselinePresent:    orTri(in.BaselinePresent),
		ObserverCanObserve: orTri(in.ObserverCanObserve),
		CadenceSource:      cadenceUnknown,
	}

	// A lane KNOWN to be out of the incident's scope is irrelevant, whatever its
	// span (constraint 7: scope relevance is a precondition, not a coverage detail).
	if a.Scope == triNo {
		a.Quality = qualityIrrelevant
		e.finishEligibility(&a, in)
		return a
	}

	// No observation at all → unavailable (a source exists for the class but nothing
	// arrived). We cannot tell unavailable from not_configured without config state,
	// so report `unavailable` — never "healthy". §7: absence is not evidence of health.
	if in.TotalCount == 0 && len(in.Observations) == 0 {
		a.Quality = qualityUnavailable
		e.finishEligibility(&a, in)
		return a
	}

	switch strategy {
	case strategyEventBased:
		e.assessEventBased(&a, in)
	case strategyFreshness:
		e.assessFreshness(&a, in, th)
	case strategyBatch:
		e.assessBatch(&a, in, th)
	default:
		e.assessContinuous(&a, in, th)
	}
	e.finishEligibility(&a, in)
	return a
}

// assessEventBased: a discrete state transition. It is a point_in_time fact, never
// judged by continuous-coverage math (constraint 6). Coverage ratio is not
// meaningful and stays RatioKnown=false.
func (e *EvidenceCoverageEngine) assessEventBased(a *CoverageAssessment, in LaneCoverageInput) {
	a.Quality = qualityPointInTime
	if t := laneMinTime(in); !t.IsZero() {
		a.OverlapStart = fmtUTC(t)
	}
	if t := laneMaxTime(in); !t.IsZero() {
		a.OverlapEnd = fmtUTC(t)
	}
}

// assessFreshness: judged by the age of the latest observation against StaleAfter.
func (e *EvidenceCoverageEngine) assessFreshness(a *CoverageAssessment, in LaneCoverageInput, th coverageThresholds) {
	last := laneMaxTime(in)
	ref := in.Now
	if ref.IsZero() {
		ref = in.WindowEnd
	}
	if last.IsZero() || ref.IsZero() {
		a.Quality = qualityUnknown
		return
	}
	age := ref.Sub(last)
	if age < 0 {
		age = 0
	}
	a.Freshness = fmtDur(age)
	a.FreshnessKnown = true
	if age > th.StaleAfter {
		a.Quality = qualityStale
		a.MissingInterval = fmt.Sprintf("last observation is %s old (stale after %s)", fmtDur(age), fmtDur(th.StaleAfter))
		return
	}
	a.Quality = qualityComplete
}

// assessBatch: a periodic batch. Fresh within the batch interval → complete, else
// stale. The batch interval comes from ScheduleInterval; unknown → StaleAfter.
func (e *EvidenceCoverageEngine) assessBatch(a *CoverageAssessment, in LaneCoverageInput, th coverageThresholds) {
	interval := in.ScheduleInterval
	if interval <= 0 {
		interval = th.StaleAfter
	} else {
		a.ExpectedCadence = fmtDur(interval)
		a.CadenceKnown = true
		a.CadenceSource = cadenceFromSchedule
	}
	last := laneMaxTime(in)
	ref := in.Now
	if ref.IsZero() {
		ref = in.WindowEnd
	}
	if last.IsZero() || ref.IsZero() {
		a.Quality = qualityUnknown
		return
	}
	age := ref.Sub(last)
	if age < 0 {
		age = 0
	}
	a.Freshness = fmtDur(age)
	a.FreshnessKnown = true
	if age > interval {
		a.Quality = qualityStale
		a.MissingInterval = fmt.Sprintf("latest batch is %s old (batch interval %s)", fmtDur(age), fmtDur(interval))
		return
	}
	a.Quality = qualityComplete
}

// assessContinuous: the core coverage math (constraint 5). Coverage = expected
// cadence + actual covered intervals INCLUDING internal gaps — never first/last
// alone. When cadence is underivable, we fall back to a span ratio and CAP the
// quality at substantial (we cannot certify "complete" without knowing whether
// internal gaps exist — honest, not fabricated).
func (e *EvidenceCoverageEngine) assessContinuous(a *CoverageAssessment, in LaneCoverageInput, th coverageThresholds) {
	ws, we := in.WindowStart, in.WindowEnd
	windowDur := we.Sub(ws)
	if ws.IsZero() || we.IsZero() || windowDur <= 0 {
		// No incident interval to measure against — either there is no established
		// incident window (no anomalous observation), or it is a single instant. In
		// both cases there is no interval a present lane could "miss", so a lane with
		// data is complete coverage (preserves the legacy min/max contract). Ratio is
		// left unknown when there was no window at all.
		a.Quality = qualityComplete
		if !ws.IsZero() && !we.IsZero() {
			a.CoverageRatio = 1
			a.RatioKnown = true
		}
		return
	}

	obs := sortedObs(in)
	cadence, csrc := e.deriveCadence(in, obs)
	if cadence > 0 {
		a.ExpectedCadence = fmtDur(cadence)
		a.CadenceKnown = true
		a.CadenceSource = csrc
	}

	var (
		ratio       float64
		lead, trail time.Duration
		internal    []gapInterval
		internalTot time.Duration
		capComplete bool // true when we could NOT verify internal gaps → cap at substantial
	)

	if cadence > 0 && len(obs) > 0 {
		ratio, lead, trail, internal, internalTot = coveredRatio(obs, ws, we, cadence)
	} else {
		// Fallback: span-only ratio from min/max. Internal gaps unverifiable → cap.
		ls, le := laneMinTime(in), laneMaxTime(in)
		if ls.IsZero() || le.IsZero() {
			a.Quality = qualityUnknown
			return
		}
		ovS, ovE := maxTime(ls, ws), minTime(le, we)
		if ovE.After(ovS) {
			ratio = ovE.Sub(ovS).Seconds() / windowDur.Seconds()
		}
		if ls.After(ws) {
			lead = ls.Sub(ws)
		}
		if we.After(le) {
			trail = we.Sub(le)
		}
		capComplete = true
	}
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}

	a.CoverageRatio = ratio
	a.RatioKnown = true
	a.InternalGaps = internal
	if internalTot > 0 {
		a.InternalGapTotal = fmtDur(internalTot)
	}
	a.OverlapStart = fmtUTC(maxTime(laneMinTime(in), ws))
	a.OverlapEnd = fmtUTC(minTime(laneMaxTime(in), we))
	if lead > 0 {
		a.LeadingGap = fmtDur(lead)
	}
	if trail > 0 {
		a.TrailingGap = fmtDur(trail)
	}
	a.MissingInterval = missingIntervalText(ws, we, laneMinTime(in), laneMaxTime(in), lead, trail, internal)

	a.Quality = classifyContinuousQuality(ratio, th, capComplete, internalTot, windowDur)
}

// classifyContinuousQuality maps a coverage ratio to a quality state using the
// tenant/class thresholds. `complete` additionally requires that internal gaps
// were VERIFIABLE (cadence known) and not material — otherwise we cap at
// substantial (constraint 5: never claim full without covered-interval proof).
func classifyContinuousQuality(ratio float64, th coverageThresholds, capComplete bool, internalTot, windowDur time.Duration) coverageQuality {
	materialInternal := windowDur > 0 && internalTot > 0 &&
		internalTot.Seconds()/windowDur.Seconds() > (1-th.Complete)
	switch {
	case ratio >= th.Complete && !capComplete && !materialInternal:
		return qualityComplete
	case ratio >= th.Substantial:
		return qualitySubstantial
	case ratio >= th.Minimal:
		return qualityPartial
	case ratio > 0:
		return qualityMinimal
	default:
		return qualityUnavailable
	}
}

// deriveCadence derives the expected cadence: prefer the configured schedule
// interval; else the median inter-arrival of the observed series (needs ≥3
// observations → ≥2 intervals); else unknown (0). NEVER first/last-only.
func (e *EvidenceCoverageEngine) deriveCadence(in LaneCoverageInput, obs []time.Time) (time.Duration, cadenceSource) {
	if in.ScheduleInterval > 0 {
		return in.ScheduleInterval, cadenceFromSchedule
	}
	if len(obs) < 3 {
		return 0, cadenceUnknown
	}
	gaps := make([]time.Duration, 0, len(obs)-1)
	for i := 1; i < len(obs); i++ {
		d := obs[i].Sub(obs[i-1])
		if d > 0 {
			gaps = append(gaps, d)
		}
	}
	if len(gaps) < 2 {
		return 0, cadenceUnknown
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	med := gaps[len(gaps)/2]
	if len(gaps)%2 == 0 {
		med = (gaps[len(gaps)/2-1] + gaps[len(gaps)/2]) / 2
	}
	if med <= 0 {
		return 0, cadenceUnknown
	}
	return med, cadenceFromArrivals
}

// coveredRatio computes coverage from covered intervals. Each observation attests
// to state for up to `coverageSpan` (1.5× cadence — absorbs jitter). Returns the
// covered/window ratio, leading + trailing gaps, and internal gaps.
func coveredRatio(obs []time.Time, ws, we time.Time, cadence time.Duration) (ratio float64, lead, trail time.Duration, internal []gapInterval, internalTot time.Duration) {
	windowDur := we.Sub(ws)
	if windowDur <= 0 {
		return 1, 0, 0, nil, 0
	}
	coverageSpan := time.Duration(float64(cadence) * 1.5)

	// Build covered intervals [t, t+coverageSpan], clipped to the window.
	type iv struct{ s, e time.Time }
	var ivs []iv
	for _, t := range obs {
		s := maxTime(t, ws)
		en := minTime(t.Add(coverageSpan), we)
		if en.After(s) {
			ivs = append(ivs, iv{s, en})
		}
	}
	if len(ivs) == 0 {
		return 0, we.Sub(ws), 0, nil, 0
	}
	// Merge overlapping intervals (obs already sorted).
	merged := []iv{ivs[0]}
	for _, cur := range ivs[1:] {
		last := &merged[len(merged)-1]
		if !cur.s.After(last.e) {
			if cur.e.After(last.e) {
				last.e = cur.e
			}
		} else {
			merged = append(merged, cur)
		}
	}
	// Covered duration + gaps.
	var covered time.Duration
	for _, m := range merged {
		covered += m.e.Sub(m.s)
	}
	lead = merged[0].s.Sub(ws)
	if lead < 0 {
		lead = 0
	}
	trail = we.Sub(merged[len(merged)-1].e)
	if trail < 0 {
		trail = 0
	}
	for i := 1; i < len(merged); i++ {
		gs, ge := merged[i-1].e, merged[i].s
		if ge.After(gs) {
			d := ge.Sub(gs)
			internal = append(internal, gapInterval{Start: fmtUTC(gs), End: fmtUTC(ge), Dur: fmtDur(d)})
			internalTot += d
		}
	}
	ratio = covered.Seconds() / windowDur.Seconds()
	return ratio, lead, trail, internal, internalTot
}

// finishEligibility computes the three eligibility verdicts + reason codes
// (constraint 7). Called for every assessment.
func (e *EvidenceCoverageEngine) finishEligibility(a *CoverageAssessment, in LaneCoverageInput) {
	scopeMismatch := a.Scope == triNo
	healthBad := a.CollectorHealth == collectorDegraded
	cannotObserve := a.ObserverCanObserve == triNo
	anomalous := in.AnomalousCount > 0

	// ---- normality: may this lane assert "measured healthy over the window"? -----
	// Requires ALL of temporal sufficiency (complete coverage) + scope relevance +
	// collector health + ability to observe. "No anomaly linked" alone never
	// qualifies (constraint 7). NOTE: unknown scope/health do NOT veto (we have no
	// evidence of mismatch/fault) — only a KNOWN negative does; this preserves the
	// "present + clean + fully-covering → normal" contract while blocking a green
	// Normal on a known scope mismatch or a known-degraded collector.
	var nReasons []string
	temporalOK := a.Quality == qualityComplete
	if !temporalOK {
		switch a.Strategy {
		case strategyEventBased:
			nReasons = append(nReasons, "point_in_time_only")
		default:
			nReasons = append(nReasons, "coverage_incomplete")
		}
	}
	if scopeMismatch {
		nReasons = append(nReasons, "scope_mismatch")
	}
	if healthBad {
		nReasons = append(nReasons, "collector_degraded")
	}
	if cannotObserve {
		nReasons = append(nReasons, "cannot_observe_condition")
	}
	if anomalous {
		nReasons = append(nReasons, "anomaly_present")
	}
	a.NormalityEligible = temporalOK && !scopeMismatch && !healthBad && !cannotObserve && !anomalous
	a.NormalityReasons = nReasons

	// ---- confidence: may this lane's evidence contribute to verdict confidence? --
	// A positive detection is eligible regardless of span; a clean lane needs at
	// least substantial coverage. Scope/health vetoes apply either way.
	var cReasons []string
	coverageOKForConfidence := anomalous || a.Quality == qualityComplete || a.Quality == qualitySubstantial ||
		(a.Strategy == strategyEventBased && a.Quality == qualityPointInTime)
	if !coverageOKForConfidence {
		cReasons = append(cReasons, "coverage_below_substantial")
	}
	if scopeMismatch {
		cReasons = append(cReasons, "scope_mismatch")
	}
	if healthBad {
		cReasons = append(cReasons, "collector_degraded")
	}
	a.ConfidenceEligible = coverageOKForConfidence && !scopeMismatch && !healthBad
	a.ConfidenceReasons = cReasons

	// ---- impact: may this lane support a definitive impact statement? ------------
	// A positive detection is always eligible; a NEGATIVE ("none detected") claim
	// requires complete coverage — this is what kills "none detected" on a lane with
	// a material trailing gap (the P-027379 flow lane, 78.8% + 2m13s gap).
	var iReasons []string
	impactOK := anomalous || a.Quality == qualityComplete
	if !impactOK {
		iReasons = append(iReasons, "coverage_incomplete_for_negative_claim")
	}
	if scopeMismatch {
		iReasons = append(iReasons, "scope_mismatch")
	}
	if healthBad {
		iReasons = append(iReasons, "collector_degraded")
	}
	a.ImpactEligible = impactOK && !scopeMismatch && !healthBad
	a.ImpactReasons = iReasons
}

// ---- legacy-field projection (keeps the current renderers stable) -------------

// legacyState projects the assessment onto the existing rcaEvidenceLane.State
// vocabulary (anomalous | normal | inconclusive | no_data). Anomalous lanes stay
// anomalous; a lane reads `normal` ONLY when normality-eligible; present-but-
// insufficient lanes are `inconclusive` (never a green Normal).
func (a CoverageAssessment) legacyState(anomalous bool) string {
	if anomalous {
		return "anomalous"
	}
	switch a.Quality {
	case qualityUnavailable, qualityNotConfigured, qualityUnknown:
		return "no_data"
	}
	if a.NormalityEligible {
		return "normal"
	}
	return "inconclusive"
}

// legacyCoverage projects the quality state onto the existing rcaEvidenceLane
// .Coverage vocabulary, extended with `point_in_time` (rendered as a note by the
// existing template — never as a green Full).
func (a CoverageAssessment) legacyCoverage() string {
	switch a.Quality {
	case qualityComplete:
		return "full"
	case qualitySubstantial, qualityPartial, qualityMinimal, qualityStale:
		return "partial"
	case qualityPointInTime:
		return "point_in_time"
	case qualityIrrelevant:
		return "not_applicable"
	default: // unavailable | not_configured | unknown
		return "none"
	}
}

// ---- helpers ------------------------------------------------------------------

func orTri(t coverageTri) coverageTri {
	if t == triYes || t == triNo {
		return t
	}
	return triUnknown
}

func orHealth(h collectorHealth) collectorHealth {
	if h == collectorHealthy || h == collectorDegraded {
		return h
	}
	return collectorUnknownHealth
}

// sortedObs returns the lane's observation timestamps sorted ascending (a copy).
func sortedObs(in LaneCoverageInput) []time.Time {
	if len(in.Observations) == 0 {
		return nil
	}
	out := make([]time.Time, 0, len(in.Observations))
	for _, t := range in.Observations {
		if !t.IsZero() {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}

// laneMinTime / laneMaxTime resolve the lane's earliest/latest observation from the
// full series when present, else from the LaneStart/LaneEnd fallback.
func laneMinTime(in LaneCoverageInput) time.Time {
	if obs := sortedObs(in); len(obs) > 0 {
		return obs[0]
	}
	return in.LaneStart
}

func laneMaxTime(in LaneCoverageInput) time.Time {
	if obs := sortedObs(in); len(obs) > 0 {
		return obs[len(obs)-1]
	}
	return in.LaneEnd
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// missingIntervalText renders the human "missing interval" summary for the legacy
// field: leading + trailing gaps, and a note when internal gaps exist.
func missingIntervalText(ws, we, ls, le time.Time, lead, trail time.Duration, internal []gapInterval) string {
	var parts []string
	if lead > 0 && !ws.IsZero() && !ls.IsZero() {
		parts = append(parts, fmt.Sprintf("%s–%s", fmtUTC(ws), fmtUTC(ls)))
	}
	if trail > 0 && !we.IsZero() && !le.IsZero() {
		parts = append(parts, fmt.Sprintf("%s–%s", fmtUTC(le), fmtUTC(we)))
	}
	if len(internal) > 0 {
		parts = append(parts, fmt.Sprintf("%d internal gap(s)", len(internal)))
	}
	return strings.Join(parts, " and ")
}
