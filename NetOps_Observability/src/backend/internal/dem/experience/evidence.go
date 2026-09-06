// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// evidence.go — EvidenceItem: the atom every experience verdict is made of.
//
// Two rules from the design of record are enforced HERE rather than in a
// caller, because a caller can forget:
//
//  1. NEGATIVE EVIDENCE IS EVIDENCE. "the checkout API's p95 did not move" and
//     "the same release is healthy on the unaffected cohort" are first-class
//     items that CONTRADICT a hypothesis. They are stored, shown and scored —
//     never dropped for being uninteresting.
//  2. MISSING EVIDENCE IS DATA. An expected source that produced nothing is
//     recorded as a [MissingEvidence] entry, lowers confidence, and can block
//     CONFIRMED outright. It is never treated as agreement.
//
// INDEPENDENCE GROUPS (the load-bearing concept): an item's IndependenceGroup
// is its MODALITY CLASS, the same vocabulary the Python correlation engine
// grades verdicts with (src/correlation/signals.py ModalityClass). Two items in
// the same group are ONE opinion however many times they are repeated — which
// is the whole point: five vantages of the same synthetic check are five
// samples of one modality, not five independent confirmations.

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Modality classes — the independence vocabulary.
//
// The first seven are byte-identical to src/correlation/signals.py's
// ModalityClass, so a verdict graded here and a verdict graded there cannot
// diverge on what "independent" means. The last three are DEM additions for
// evidence the correlation engine does not yet produce; each is declared
// SUPPORT-ONLY below, so adding them can only ever LOWER a verdict, never raise
// one past a gate the Python engine would have held shut.
const (
	ModalityActiveProbe        = "active_probe"        // a synthetic check from a vantage
	ModalityPassiveFlow        = "passive_flow"        // flow records / ART
	ModalityControlPlane       = "control_plane"       // routing, BGP, adjacency
	ModalityDeviceTelemetry    = "device_telemetry"    // SNMP/gNMI/syslog from the device
	ModalityManagementPlane    = "management_plane"    // an NMS controller's own opinion
	ModalityActiveVerification = "active_verification" // the device's own read-only answer
	ModalitySecurity           = "security"            // a rule/benchmark verdict

	// ModalityRealUser is first-party RUM (Tier 4). A browser beacon is neither
	// an active probe nor a flow record: it is the only class that observes the
	// experience from the seat it is actually had in, which is exactly why it
	// is allowed to ANCHOR a verdict. When the RUM producer ships, the same
	// class must be added to signals.py so both graders keep agreeing.
	ModalityRealUser = "real_user"

	// ModalityChangeRecord is a deployment / config / flag / cloud / route
	// change. SUPPORT-ONLY on purpose: a change is not a measurement of the
	// experience, and "it happened just before" is correlation by clock. This
	// constant is what makes "temporal proximity alone cannot confirm
	// causality" a structural fact instead of a review comment.
	ModalityChangeRecord = "change_record"

	// ModalityBusiness is a business outcome (orders, logins, transactions).
	// SUPPORT-ONLY: it measures the CONSEQUENCE, never the mechanism.
	ModalityBusiness = "business"
)

// anchorModalities are the classes that may anchor a CONFIRMED verdict.
//
// THIS SET IS DELIBERATELY STRICTER THAN THE CORRELATION ENGINE'S, and the
// difference is worth stating plainly rather than glossing as "the same rule".
// In src/correlation/verdicts.py only two things cannot anchor: a probe below
// CONFIRM_AUTHORITIES, and a support-only active-verification witness —
// `management_plane` and `security` are ordinary trusted modalities there, and
// "a controller alone caps at suspected" follows from the two-modality rule
// rather than from a per-class veto.
//
// DEM refuses those two, plus `active_verification`, as ANCHORS because an
// experience verdict is a claim about what a user experienced: a controller's
// own summary, a device's answer about itself and a rule engine's verdict are
// all second-hand about that, however trustworthy they are about their own
// subject. `change_record` and `business` are refused for the same reason one
// step further out — a change is not a measurement of the experience, and a
// business outcome measures the consequence rather than the mechanism.
//
// The consequence is one-directional and is the safe direction: a DEM verdict
// can be LESS confident than the correlation engine's on the same evidence, and
// never more. The two graders also answer different questions — this one grades
// DEM's hypotheses over DEM's evidence, while `run_window` publishes the
// winning SIGNATURE's gate after a topology-grounding cap — so a correlation
// object's tier and an experience incident's tier are different claims about
// different things and must never be shown as one number.
var anchorModalities = map[string]bool{
	ModalityActiveProbe:     true,
	ModalityPassiveFlow:     true,
	ModalityControlPlane:    true,
	ModalityDeviceTelemetry: true,
	ModalityRealUser:        true,
}

var knownModalities = map[string]bool{
	ModalityActiveProbe: true, ModalityPassiveFlow: true, ModalityControlPlane: true,
	ModalityDeviceTelemetry: true, ModalityManagementPlane: true,
	ModalityActiveVerification: true, ModalitySecurity: true,
	ModalityRealUser: true, ModalityChangeRecord: true, ModalityBusiness: true,
}

// ValidModality reports whether m is a declared modality class.
func ValidModality(m string) bool { return knownModalities[m] }

// MayAnchorVerdict reports whether modality class m can anchor CONFIRMED.
func MayAnchorVerdict(m string) bool { return anchorModalities[m] }

// Evidence kinds — WHAT the item claims, independent of who produced it.
const (
	KindSyntheticResult  = "synthetic_result"  // a check succeeded/failed from a vantage
	KindJourneyOutcome   = "journey_outcome"   // a journey traversal succeeded/failed at a step
	KindPathObservation  = "path_observation"  // an ordered path measurement (pathgraph)
	KindPathDegradation  = "path_degradation"  // loss/latency at a named hop or seam
	KindServiceHealth    = "service_health"    // a backend service's own health/latency
	KindChange           = "change"            // a ChangeEvent tied to the window
	KindCohortComparison = "cohort_comparison" // "this cohort moved, that one did not"
	KindRealUserMetric   = "real_user_metric"  // RUM: web vitals, error rate, page timing
	KindBusinessOutcome  = "business_outcome"  // orders/logins/transactions
	KindCorrelation      = "correlation"       // a correlation object's own verdict
	KindSourceHealth     = "source_health"     // a telemetry source's own state
)

var knownEvidenceKinds = map[string]bool{
	KindSyntheticResult: true, KindJourneyOutcome: true, KindPathObservation: true,
	KindPathDegradation: true, KindServiceHealth: true, KindChange: true,
	KindCohortComparison: true, KindRealUserMetric: true, KindBusinessOutcome: true,
	KindCorrelation: true, KindSourceHealth: true,
}

// ValidEvidenceKind reports whether k is a declared evidence kind.
func ValidEvidenceKind(k string) bool { return knownEvidenceKinds[k] }

// Stance is what the item does to a hypothesis. Kept as an explicit field on
// the item as WELL as the supports/contradicts id lists, so an item that
// belongs to no hypothesis yet still declares which way it points.
const (
	StanceSupports    = "supports"
	StanceContradicts = "contradicts"
	StanceNeutral     = "neutral" // context: rendered, never scored
)

// EvidenceItem is one graded observation attached to an experience incident.
type EvidenceItem struct {
	ID         string `json:"id"`
	TenantID   string `json:"tenant_id"`
	IncidentID string `json:"incident_id,omitempty"`

	Kind string `json:"kind"`
	// Entity is what the item is ABOUT — a target id, a seam id, a hop address,
	// a service name, a journey step. Opaque here; nothing parses it.
	Entity string `json:"entity,omitempty"`
	// EntityKind names the entity's vocabulary so the UI can link it: target |
	// seam | hop | service | journey_step | cohort | change | source.
	EntityKind string `json:"entity_kind,omitempty"`

	Summary string `json:"summary"` // the operator-facing sentence
	Detail  string `json:"detail,omitempty"`

	// Value / Baseline / Deviation are optional and are only meaningful
	// together. Deviation is in baseline sigmas or, when no sigma exists, the
	// ratio value/baseline − 1. HasValue distinguishes "0" from "not set" —
	// pointers rather than sentinels, because 0 is a legitimate measurement.
	Value     *float64 `json:"value,omitempty"`
	Baseline  *float64 `json:"baseline,omitempty"`
	Deviation *float64 `json:"deviation,omitempty"`
	Unit      string   `json:"unit,omitempty"`

	Stance                string   `json:"stance"`
	SupportsHypotheses    []string `json:"supports_hypothesis_ids,omitempty"`
	ContradictsHypotheses []string `json:"contradicts_hypothesis_ids,omitempty"`

	// Decisive marks a contradiction that REFUTES rather than merely weakens —
	// the owner's "same release is healthy on the unaffected cohort". A decisive
	// contradiction drives the hypothesis to REJECTED regardless of how much
	// supporting evidence it has, because supporting evidence for a cause that
	// demonstrably did not act is not evidence at all.
	Decisive bool `json:"decisive,omitempty"`

	// ── scope: WHERE this observation applies ──
	// These are what let an incident be assembled per application / per site /
	// per journey without a caller having to pre-group the evidence, and what
	// let a cohort comparison be made at all.
	App       string `json:"app,omitempty"`
	Site      string `json:"site,omitempty"`
	JourneyID string `json:"journey_id,omitempty"`
	StepID    string `json:"step_id,omitempty"`
	Cohort    Cohort `json:"cohort,omitempty"`

	// ── causal pointer: WHAT this observation implicates ──
	// A SUPPORTING item names the cause class (and, where it knows it, the
	// concrete entity and the owning seam) it points at. A CONTRADICTING item
	// names the cause classes it refutes. Hypotheses are generated from these
	// declarations, so the mapping from an observation to a blamed thing lives
	// with the adapter that produced the observation and can be reviewed —
	// never inside the ranker as an inline guess.
	CauseClass        string   `json:"cause_class,omitempty"`
	CauseEntity       string   `json:"cause_entity,omitempty"`
	Seam              string   `json:"seam,omitempty"`
	Owner             string   `json:"owner,omitempty"`
	ContradictsCauses []string `json:"contradicts_causes,omitempty"`

	// IndependenceGroup is the MODALITY CLASS. Two items sharing it are one
	// opinion, no matter how many observers reported it.
	IndependenceGroup string `json:"independence_group"`
	// Observer is the distinct vantage/collector. Two items of the same
	// modality from two observers are two samples; the independence rule needs
	// BOTH a second modality and a second observer.
	Observer string `json:"observer,omitempty"`

	// Reliability is how much this class of observation is trusted, 0..1. It is
	// a property of the SOURCE, not of the number: a controller's own summary
	// and a packet measured on the wire are not equally strong claims.
	Reliability float64 `json:"reliability"`
	// ExpectedIntervalSec is how often this source should produce. It is what
	// turns an age into a FRESHNESS: 90 s old is fresh for a daily change feed
	// and stale for a 15 s probe. 0 = no cadence declared, and freshness then
	// decays on the package default rather than on an invented cadence.
	ExpectedIntervalSec int `json:"expected_interval_sec,omitempty"`

	Provenance `json:"provenance"`
}

// Reliability defaults per source. Declared as DATA so the numbers are
// reviewable in one place instead of being scattered through the scorer.
//
// The ordering is the argument: a measurement taken on the path (probe, flow,
// path observation) outranks a controller's summary of it, which outranks an
// inference from a change record. Nothing here is 1.0 — no single source is
// beyond doubt, and a 1.0 would let one item saturate support on its own.
var sourceReliability = map[string]float64{
	SourceSynthetic:   0.90,
	SourcePathGraph:   0.90,
	SourceRUM:         0.95, // the experience as actually had, from the seat
	SourceFlow:        0.85,
	SourceBGP:         0.85,
	SourceCorrelation: 0.80,
	SourceServiceHTTP: 0.80,
	SourceSDWAN:       0.75,
	SourceWireless:    0.75,
	SourceAgent:       0.80,
	SourceConfigDrift: 0.70,
	SourceCloud:       0.70,
	SourceManual:      0.60,
}

// DefaultReliability returns the declared reliability for a source, or a
// deliberately modest 0.5 for one nobody graded — an ungraded source must not
// carry the weight of a graded one.
func DefaultReliability(source string) float64 {
	if r, ok := sourceReliability[source]; ok {
		return r
	}
	return 0.5
}

// freshnessHalfLife is how long an item takes to lose half its weight when its
// source declared no cadence. Chosen to match the shortest experience window
// (1 h) so an hour-old fact carries half the weight of a fresh one.
const freshnessHalfLife = time.Hour

// Freshness grades how current the item is at now, 0..1.
//
// With a declared cadence the item is FULLY fresh for one interval and decays
// to zero over ten — a source that missed one cycle is not yet suspect, one
// that missed ten has stopped. With no cadence it halves every hour. It never
// returns a negative weight and never returns exactly 0 for an item inside its
// own interval.
func (e EvidenceItem) Freshness(now time.Time) float64 {
	age := e.Age(now)
	if e.ExpectedIntervalSec > 0 {
		iv := time.Duration(e.ExpectedIntervalSec) * time.Second
		switch {
		case age <= iv:
			return 1
		case age >= 10*iv:
			return 0
		default:
			return clamp01(1 - float64(age-iv)/float64(9*iv))
		}
	}
	if age <= 0 {
		return 1
	}
	// Exponential half-life without math.Exp's opacity: 0.5 ^ (age/halfLife),
	// computed as a plain power so the docs can state the number.
	return clamp01(pow(0.5, float64(age)/float64(freshnessHalfLife)))
}

// Weight is the item's contribution to a verdict: reliability × freshness.
// A neutral item weighs nothing — it is context for a human, not input to a
// number, and the distinction is deliberate.
func (e EvidenceItem) Weight(now time.Time) float64 {
	if e.Stance == StanceNeutral {
		return 0
	}
	r := e.Reliability
	if r <= 0 {
		r = DefaultReliability(e.Source)
	}
	return clamp01(r) * e.Freshness(now)
}

// Validate normalizes the item and refuses one that cannot be graded.
func (e *EvidenceItem) Validate() error {
	e.ID = clip(strings.TrimSpace(e.ID), MaxIDBytes)
	if e.ID == "" {
		return errors.New("evidence: id is required")
	}
	e.TenantID = strings.ToLower(strings.TrimSpace(e.TenantID))
	e.IncidentID = clip(strings.TrimSpace(e.IncidentID), MaxIDBytes)
	e.Kind = strings.ToLower(strings.TrimSpace(e.Kind))
	if !ValidEvidenceKind(e.Kind) {
		return fmt.Errorf("evidence %s: unknown kind %q", e.ID, clip(e.Kind, 32))
	}
	e.Entity = clip(strings.TrimSpace(e.Entity), MaxIDBytes)
	e.EntityKind = clip(strings.ToLower(strings.TrimSpace(e.EntityKind)), MaxLabelBytes)
	e.Summary = clip(strings.TrimSpace(e.Summary), MaxSummaryBytes)
	if e.Summary == "" {
		return fmt.Errorf("evidence %s: a summary is required (evidence an operator cannot read is not evidence)", e.ID)
	}
	e.Detail = clip(strings.TrimSpace(e.Detail), MaxDetailBytes)
	e.Unit = clip(strings.TrimSpace(e.Unit), MaxLabelBytes)
	e.Stance = strings.ToLower(strings.TrimSpace(e.Stance))
	switch e.Stance {
	case StanceSupports, StanceContradicts, StanceNeutral:
	case "":
		e.Stance = StanceNeutral
	default:
		return fmt.Errorf("evidence %s: stance must be supports|contradicts|neutral (got %q)", e.ID, clip(e.Stance, 32))
	}
	if e.Decisive && e.Stance != StanceContradicts {
		return fmt.Errorf("evidence %s: only a contradicting item may be decisive", e.ID)
	}
	e.IndependenceGroup = strings.ToLower(strings.TrimSpace(e.IndependenceGroup))
	if !ValidModality(e.IndependenceGroup) {
		return fmt.Errorf("evidence %s: unknown independence_group %q (it is the modality class)", e.ID, clip(e.IndependenceGroup, 32))
	}
	e.Observer = clip(strings.TrimSpace(e.Observer), MaxIDBytes)
	if e.Reliability < 0 || e.Reliability > 1 {
		return fmt.Errorf("evidence %s: reliability must be 0..1", e.ID)
	}
	if e.Reliability == 0 {
		e.Reliability = DefaultReliability(e.Source)
	}
	if e.ExpectedIntervalSec < 0 {
		return fmt.Errorf("evidence %s: expected_interval_sec must not be negative", e.ID)
	}
	e.App, e.Site = labelSafe(e.App), labelSafe(e.Site)
	e.JourneyID = clip(strings.TrimSpace(e.JourneyID), MaxIDBytes)
	e.StepID = labelSafe(e.StepID)
	e.Seam = clip(strings.TrimSpace(e.Seam), MaxLabelBytes)
	e.Owner = clip(strings.TrimSpace(e.Owner), MaxLabelBytes)
	e.CauseEntity = clip(strings.TrimSpace(e.CauseEntity), MaxIDBytes)
	if e.CauseClass != "" {
		e.CauseClass = strings.ToLower(strings.TrimSpace(e.CauseClass))
		if !ValidCauseClass(e.CauseClass) {
			return fmt.Errorf("evidence %s: unknown cause_class %q", e.ID, clip(e.CauseClass, 40))
		}
	}
	for i, c := range e.ContradictsCauses {
		c = strings.ToLower(strings.TrimSpace(c))
		if !ValidCauseClass(c) {
			return fmt.Errorf("evidence %s: unknown contradicted cause_class %q", e.ID, clip(c, 40))
		}
		e.ContradictsCauses[i] = c
	}
	e.SupportsHypotheses = dedupIDs(e.SupportsHypotheses)
	e.ContradictsHypotheses = dedupIDs(e.ContradictsHypotheses)
	return e.Provenance.Validate()
}

// MissingEvidence is an expected source that produced NOTHING for the window.
// It is a first-class record, not an absence: it is listed on the hypothesis,
// it lowers confidence, and when Required it blocks CONFIRMED entirely.
type MissingEvidence struct {
	// Source is the producer that should have reported (a Provenance source).
	Source string `json:"source"`
	// IndependenceGroup is the modality class the missing evidence would have
	// carried — which is what makes "we are missing our only second opinion"
	// mechanically visible.
	IndependenceGroup string `json:"independence_group,omitempty"`
	Reason            string `json:"reason"`             // not_configured | no_data | stale | permission_denied | error | not_supported
	Detail            string `json:"detail,omitempty"`   // the operator sentence
	Required          bool   `json:"required,omitempty"` // its absence BLOCKS confirmation
}

// Missing-evidence reasons. They mirror the appobs readiness vocabulary the
// Data Health surface already speaks, so one word means one thing everywhere.
const (
	MissingNotConfigured    = "not_configured"
	MissingNoData           = "no_data"
	MissingStale            = "stale"
	MissingPermissionDenied = "permission_denied"
	MissingError            = "error"
	MissingNotSupported     = "not_supported"
)

// Validate refuses a missing-evidence record that names no source or reason —
// "something is missing" is not a diagnosis.
func (m *MissingEvidence) Validate() error {
	m.Source = strings.ToLower(strings.TrimSpace(m.Source))
	if !ValidSource(m.Source) {
		return fmt.Errorf("missing evidence: unknown source %q", clip(m.Source, 32))
	}
	m.IndependenceGroup = strings.ToLower(strings.TrimSpace(m.IndependenceGroup))
	if m.IndependenceGroup != "" && !ValidModality(m.IndependenceGroup) {
		return fmt.Errorf("missing evidence: unknown independence_group %q", clip(m.IndependenceGroup, 32))
	}
	switch m.Reason {
	case MissingNotConfigured, MissingNoData, MissingStale, MissingPermissionDenied,
		MissingError, MissingNotSupported:
	default:
		return fmt.Errorf("missing evidence: unknown reason %q", clip(m.Reason, 32))
	}
	m.Detail = clip(strings.TrimSpace(m.Detail), MaxDetailBytes)
	return nil
}

// Independence summarises the modality/observer spread of a set of items. It is
// the Go twin of src/correlation/verdicts.EvidenceCoverage and answers exactly
// one question: may this evidence anchor a CONFIRMED verdict?
type Independence struct {
	// AnchorModalities / Modalities are the DISTINCT classes present among the
	// supporting items — anchor-capable ones and all of them.
	AnchorModalities []string `json:"anchor_modalities"`
	Modalities       []string `json:"modalities"`
	Observers        []string `json:"observers"`
	// IndependentPair names the two items that satisfy the rule (different
	// anchor modality AND different observer). Empty when none does — and the
	// emptiness is the reason a verdict stays SUSPECTED.
	IndependentPair []string `json:"independent_pair,omitempty"`
	// Reasons are the mechanical explanations for a failed gate. They are the
	// sentences the UI shows next to "not confirmed" — never a generic label.
	Reasons []string `json:"reasons,omitempty"`
}

// Satisfied reports whether the independence rule is met: at least two distinct
// ANCHOR modality classes, at least two distinct observers, and a concrete pair
// that is both.
func (i Independence) Satisfied() bool { return len(i.IndependentPair) == 2 }

// AssessIndependence computes the coverage of the SUPPORTING items in set.
//
// Items whose modality class cannot anchor a verdict are counted in Modalities
// (they are real corroboration and are shown) but never in AnchorModalities —
// which is how a wall of change records and business outcomes fails to confirm
// anything no matter how large it is.
func AssessIndependence(items []EvidenceItem) Independence {
	var out Independence
	anchors := map[string]bool{}
	all := map[string]bool{}
	obs := map[string]bool{}
	type cand struct{ id, modality, observer string }
	cands := make([]cand, 0, len(items))
	for _, it := range items {
		if it.Stance != StanceSupports {
			continue
		}
		all[it.IndependenceGroup] = true
		observer := it.Observer
		if observer == "" {
			// An item that will not name its observer cannot prove it is a
			// SECOND opinion, so it is treated as sharing one anonymous
			// vantage with every other unnamed item (§3: no benefit of doubt).
			observer = "unnamed:" + it.IndependenceGroup
		}
		obs[observer] = true
		if MayAnchorVerdict(it.IndependenceGroup) {
			anchors[it.IndependenceGroup] = true
			cands = append(cands, cand{id: it.ID, modality: it.IndependenceGroup, observer: observer})
		}
	}
	out.AnchorModalities, out.Modalities, out.Observers = sortedKeys(anchors), sortedKeys(all), sortedKeys(obs)

	for i := 0; i < len(cands) && out.IndependentPair == nil; i++ {
		for j := i + 1; j < len(cands); j++ {
			if cands[i].modality != cands[j].modality && cands[i].observer != cands[j].observer {
				out.IndependentPair = []string{cands[i].id, cands[j].id}
				break
			}
		}
	}
	switch {
	case len(out.Modalities) == 0:
		out.Reasons = append(out.Reasons, "no supporting evidence")
	case len(out.AnchorModalities) == 0:
		out.Reasons = append(out.Reasons,
			"every supporting observation is of a class that can corroborate but never confirm (a change record or a business outcome is not a measurement of the experience)")
	case len(out.AnchorModalities) < 2:
		out.Reasons = append(out.Reasons,
			"only one independent modality class observed it — one kind of instrument agreeing with itself is one opinion")
	}
	if len(out.Observers) < 2 && len(out.Modalities) > 0 {
		out.Reasons = append(out.Reasons, "only one observer reported it")
	}
	if len(out.AnchorModalities) >= 2 && len(out.Observers) >= 2 && out.IndependentPair == nil {
		out.Reasons = append(out.Reasons,
			"the second modality came from the same observer, so the two observations are not independent")
	}
	return out
}

// ── small helpers (kept local; CLAUDE.md §2 forbids a shared "utils") ────────

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

// pow is x^y for x in (0,1] and y >= 0, by repeated squaring on the integer
// part and a bounded binary refinement on the fraction. math.Pow would do, but
// this keeps the decay function auditable to the decimal the docs quote and
// avoids any platform-dependent last-bit difference in a stored confidence.
func pow(x, y float64) float64 {
	if x <= 0 {
		return 0
	}
	if y <= 0 {
		return 1
	}
	res := 1.0
	base := x
	n := int(y)
	for i := 0; i < n && i < 64; i++ {
		res *= base
	}
	frac := y - float64(n)
	// 12 halvings of the exponent resolve the fraction to ~2^-12, far finer
	// than the two decimal places a confidence is ever reported to.
	for i := 0; i < 12 && frac > 0; i++ {
		base = sqrt(base)
		frac *= 2
		if frac >= 1 {
			res *= base
			frac--
		}
	}
	return res
}

// sqrt is Newton's method, bounded. Same reasoning as pow.
func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	g := x
	for i := 0; i < 24; i++ {
		g = 0.5 * (g + x/g)
	}
	return g
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func dedupIDs(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = clip(strings.TrimSpace(v), MaxIDBytes)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
		if len(out) >= MaxListLen {
			break
		}
	}
	sort.Strings(out)
	return out
}

func round2(v float64) float64 {
	return float64(int64(v*100+0.5*sign(v))) / 100
}

func sign(v float64) float64 {
	if v < 0 {
		return -1
	}
	return 1
}
