package experience

// journey.go — JourneyDefinition / JourneyObservation / JourneyHealth.
//
// A journey is the workflow a person is actually trying to complete: search →
// product → cart → authentication → checkout → payment → confirmation. It is
// NOT a linear Sankey (the owner's Phase C.3 is explicit): steps branch, are
// optional, and may loop, and a definition that cannot express that would force
// every real workflow to be lied about at modelling time.
//
// WHERE THE OBSERVATIONS COME FROM, TODAY
// Correlix has one experience producer in production: the synthetic prober. So
// a journey step BINDS to a catalogue target, and [JourneyHealth] is computed
// from that target's measured window — availability, p95 against the declared
// budget, and whether it was measured at all. That is a real, honest journey
// health today. A per-traversal [JourneyObservation] needs per-run records
// (SyntheticRun) or first-party RUM; the type and its constructor exist and are
// tested, and the surfaces that would serve them say "not measured — reason"
// until a producer exists. Nothing here fabricates a traversal.

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Bounds. A journey with 200 steps is a process diagram, not a user journey.
const (
	MaxJourneySteps        = 40
	MaxJourneysPerTenant   = 100
	MaxStepNextFanout      = 8
	MaxCohortDimensionsLen = 12
)

// Business importance — drives triage order and the coverage model's "which
// untested action matters most".
const (
	ImportanceCritical = "critical"
	ImportanceHigh     = "high"
	ImportanceNormal   = "normal"
	ImportanceLow      = "low"
)

var knownImportance = map[string]bool{
	ImportanceCritical: true, ImportanceHigh: true, ImportanceNormal: true, ImportanceLow: true,
}

// ImportanceWeight ranks importance for ordering. Higher is more important.
func ImportanceWeight(i string) int {
	switch i {
	case ImportanceCritical:
		return 3
	case ImportanceHigh:
		return 2
	case ImportanceNormal:
		return 1
	default:
		return 0
	}
}

// JourneyStep is one node of the journey graph.
type JourneyStep struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// Optional marks a step a traversal may legitimately skip. An optional step
	// that fails does not fail the journey; it is still counted and shown.
	Optional bool `json:"optional,omitempty"`
	// Next lists the step ids that may follow. A step may appear in its own
	// reachable set (a retry loop) — loops are legal and are NOT an error.
	Next []string `json:"next,omitempty"`
	// TerminalSuccess / TerminalFailure mark the two kinds of end. A step may be
	// neither (it continues) but never both.
	TerminalSuccess bool `json:"terminal_success,omitempty"`
	TerminalFailure bool `json:"terminal_failure,omitempty"`

	// TargetID binds the step to an internal/dem catalogue target — the step's
	// measurement today. Empty = the step is DECLARED but NOT MEASURED, which
	// the health surface reports as a coverage gap rather than as success.
	TargetID string `json:"target_id,omitempty"`

	// SLOSuccessPct / SLOLatencyMs are this step's own budget. 0 = inherit the
	// journey's; there is no invented default.
	SLOSuccessPct float64 `json:"slo_success_pct,omitempty"`
	SLOLatencyMs  float64 `json:"slo_latency_ms,omitempty"`
}

// ExperienceSLO is the journey- or app-level objective a score is judged
// against. It is DATA (per tenant, per journey), never a constant in code.
type ExperienceSLO struct {
	SuccessPct float64 `json:"success_pct"`          // e.g. 99.0
	LatencyMs  float64 `json:"latency_ms,omitempty"` // p95 objective; 0 = none declared
	Window     string  `json:"window,omitempty"`     // "1h" | "24h" — the window it is stated over
}

// Declared reports whether an objective was actually set by an operator. An
// undeclared SLO is never substituted with a plausible number: a score against
// a threshold nobody set is a fiction.
func (s ExperienceSLO) Declared() bool { return s.SuccessPct > 0 }

// JourneyDefinition is one declared workflow.
type JourneyDefinition struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	Name        string `json:"name"`
	App         string `json:"app,omitempty"`
	Description string `json:"description,omitempty"`

	BusinessImportance string `json:"business_importance"`
	// BusinessValuePerSuccess is the value of ONE successful traversal, in
	// Currency. Optional: business impact is shown only when the operator
	// declared a value — an invented one is worse than none.
	BusinessValuePerSuccess float64 `json:"business_value_per_success,omitempty"`
	Currency                string  `json:"currency,omitempty"`

	EntryStepID string        `json:"entry_step_id"`
	Steps       []JourneyStep `json:"steps"`
	SLO         ExperienceSLO `json:"slo"`

	// Version increments on every definition change. An observation records the
	// version it traversed, so a journey redesign never silently rewrites
	// history (Phase B.E: observations are immutable facts).
	Version int `json:"version"`

	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Validate normalizes the definition and refuses a graph that cannot be walked.
func (j *JourneyDefinition) Validate() error {
	j.TenantID = strings.ToLower(strings.TrimSpace(j.TenantID))
	if j.TenantID == "" || j.TenantID == "*" {
		return errors.New("journey: a concrete tenant is required")
	}
	j.Name = clip(strings.TrimSpace(j.Name), MaxLabelBytes)
	if j.Name == "" {
		return errors.New("journey: name is required")
	}
	j.App = labelSafe(j.App)
	j.Description = clip(strings.TrimSpace(j.Description), MaxDetailBytes)
	j.BusinessImportance = strings.ToLower(strings.TrimSpace(j.BusinessImportance))
	if j.BusinessImportance == "" {
		j.BusinessImportance = ImportanceNormal
	}
	if !knownImportance[j.BusinessImportance] {
		return fmt.Errorf("journey: business_importance must be critical|high|normal|low (got %q)", clip(j.BusinessImportance, 32))
	}
	if j.BusinessValuePerSuccess < 0 {
		return errors.New("journey: business_value_per_success must not be negative")
	}
	j.Currency = clip(strings.ToUpper(strings.TrimSpace(j.Currency)), 8)
	if j.BusinessValuePerSuccess > 0 && j.Currency == "" {
		return errors.New("journey: a business value needs a currency (an unlabelled number is not an amount)")
	}
	if j.SLO.SuccessPct < 0 || j.SLO.SuccessPct > 100 {
		return errors.New("journey: slo.success_pct must be 0..100")
	}
	if j.SLO.LatencyMs < 0 {
		return errors.New("journey: slo.latency_ms must not be negative")
	}
	if len(j.Steps) == 0 {
		return errors.New("journey: at least one step is required")
	}
	if len(j.Steps) > MaxJourneySteps {
		return fmt.Errorf("journey: at most %d steps", MaxJourneySteps)
	}

	ids := make(map[string]bool, len(j.Steps))
	for i := range j.Steps {
		s := &j.Steps[i]
		s.ID = labelSafe(s.ID)
		if s.ID == "" {
			return fmt.Errorf("journey: step %d has no id", i+1)
		}
		if ids[s.ID] {
			return fmt.Errorf("journey: duplicate step id %q", clip(s.ID, 40))
		}
		ids[s.ID] = true
		s.Label = clip(strings.TrimSpace(s.Label), MaxLabelBytes)
		if s.Label == "" {
			s.Label = s.ID
		}
		s.TargetID = clip(strings.TrimSpace(s.TargetID), MaxIDBytes)
		if s.TerminalSuccess && s.TerminalFailure {
			return fmt.Errorf("journey: step %q cannot be both a success and a failure terminal", clip(s.ID, 40))
		}
		if len(s.Next) > MaxStepNextFanout {
			return fmt.Errorf("journey: step %q fans out to more than %d steps", clip(s.ID, 40), MaxStepNextFanout)
		}
		if s.SLOSuccessPct < 0 || s.SLOSuccessPct > 100 {
			return fmt.Errorf("journey: step %q slo_success_pct must be 0..100", clip(s.ID, 40))
		}
		if s.SLOLatencyMs < 0 {
			return fmt.Errorf("journey: step %q slo_latency_ms must not be negative", clip(s.ID, 40))
		}
	}
	// Edges must land somewhere real. A dangling edge is a journey that cannot
	// be walked, and walking it is the only thing a journey is for.
	for _, s := range j.Steps {
		for _, n := range s.Next {
			if !ids[labelSafe(n)] {
				return fmt.Errorf("journey: step %q points at unknown step %q", clip(s.ID, 40), clip(n, 40))
			}
		}
	}
	j.EntryStepID = labelSafe(j.EntryStepID)
	if j.EntryStepID == "" {
		j.EntryStepID = j.Steps[0].ID
	}
	if !ids[j.EntryStepID] {
		return fmt.Errorf("journey: entry_step_id %q is not one of the steps", clip(j.EntryStepID, 40))
	}
	terminal := false
	for _, s := range j.Steps {
		if s.TerminalSuccess {
			terminal = true
			break
		}
	}
	if !terminal {
		return errors.New("journey: at least one step must be a success terminal (a journey with no way to succeed cannot have a success rate)")
	}
	if j.Version <= 0 {
		j.Version = 1
	}
	return nil
}

// Step returns the step with id, and whether it exists.
func (j JourneyDefinition) Step(id string) (JourneyStep, bool) {
	for _, s := range j.Steps {
		if s.ID == id {
			return s, true
		}
	}
	return JourneyStep{}, false
}

// MeasuredSteps counts the steps bound to a measurement target — the coverage
// numerator the Synthetics tab reports against.
func (j JourneyDefinition) MeasuredSteps() int {
	n := 0
	for _, s := range j.Steps {
		if s.TargetID != "" {
			n++
		}
	}
	return n
}

// Cohort is the population a measurement belongs to. Cohorts are the reason a
// deployment can be RULED OUT: "the same release is healthy on another ISP" is
// a cohort comparison, and without cohorts it cannot be stated.
type Cohort struct {
	Site        string `json:"site,omitempty"`
	ISP         string `json:"isp,omitempty"` // provider name or ASN
	Region      string `json:"region,omitempty"`
	DeviceType  string `json:"device_type,omitempty"`
	Browser     string `json:"browser,omitempty"`
	AppVersion  string `json:"app_version,omitempty"`
	NetworkType string `json:"network_type,omitempty"` // wifi | wired | cellular | vpn
	FeatureFlag string `json:"feature_flag,omitempty"`
}

// Key is the cohort's stable, human-readable identity. Empty dimensions are
// omitted rather than rendered as "unknown", so two cohorts differing only in a
// dimension nobody recorded are one cohort, not two.
func (c Cohort) Key() string {
	parts := make([]string, 0, 8)
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	add("site", c.Site)
	add("isp", c.ISP)
	add("region", c.Region)
	add("device", c.DeviceType)
	add("browser", c.Browser)
	add("version", c.AppVersion)
	add("network", c.NetworkType)
	add("flag", c.FeatureFlag)
	if len(parts) == 0 {
		return "all"
	}
	return strings.Join(parts, " · ")
}

// Empty reports whether no dimension was recorded.
func (c Cohort) Empty() bool { return c.Key() == "all" }

// JourneyObservation is ONE actual traversal. Immutable (Phase B.E).
type JourneyObservation struct {
	ID             string `json:"id"`
	TenantID       string `json:"tenant_id"`
	JourneyID      string `json:"journey_id"`
	JourneyVersion int    `json:"journey_version"`

	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`

	Success   bool `json:"success"`
	Abandoned bool `json:"abandoned,omitempty"`
	// FailedStepID names where it stopped. Empty on success.
	FailedStepID string `json:"failed_step_id,omitempty"`
	// StepsCompleted lists the step ids traversed, in order — branching is
	// recorded as what actually happened, not fitted to a fixed column set.
	StepsCompleted []string `json:"steps_completed,omitempty"`
	DurationMs     float64  `json:"duration_ms,omitempty"`
	Errors         []string `json:"errors,omitempty"`

	BusinessValue float64 `json:"business_value,omitempty"`
	Currency      string  `json:"currency,omitempty"`

	// Correlation handles: the trace ids and the path observation this
	// traversal rode, so the incident view can join them without guessing.
	TraceIDs          []string `json:"trace_ids,omitempty"`
	PathObservationID string   `json:"path_observation_id,omitempty"`
	// SyntheticRunID is set when the traversal was a synthetic run rather than
	// a person. The distinction is never hidden: a synthetic success is not
	// proof that a person succeeded.
	SyntheticRunID string `json:"synthetic_run_id,omitempty"`

	Cohort     Cohort `json:"cohort"`
	Provenance `json:"provenance"`
}

// Validate refuses an observation that contradicts itself.
func (o *JourneyObservation) Validate() error {
	o.ID = clip(strings.TrimSpace(o.ID), MaxIDBytes)
	if o.ID == "" {
		return errors.New("journey observation: id is required")
	}
	o.TenantID = strings.ToLower(strings.TrimSpace(o.TenantID))
	o.JourneyID = clip(strings.TrimSpace(o.JourneyID), MaxIDBytes)
	if o.JourneyID == "" {
		return fmt.Errorf("journey observation %s: journey_id is required", o.ID)
	}
	if o.StartedAt.IsZero() {
		return fmt.Errorf("journey observation %s: started_at is required", o.ID)
	}
	if !o.EndedAt.IsZero() && o.EndedAt.Before(o.StartedAt) {
		return fmt.Errorf("journey observation %s: ended_at precedes started_at", o.ID)
	}
	if o.Success && o.FailedStepID != "" {
		return fmt.Errorf("journey observation %s: a successful traversal cannot name a failed step", o.ID)
	}
	if !o.Success && o.FailedStepID == "" && !o.Abandoned {
		return fmt.Errorf("journey observation %s: a failed traversal must name where it failed, or be marked abandoned", o.ID)
	}
	o.FailedStepID = labelSafe(o.FailedStepID)
	o.DurationMs = nonNegative(o.DurationMs)
	o.BusinessValue = nonNegative(o.BusinessValue)
	o.Currency = clip(strings.ToUpper(strings.TrimSpace(o.Currency)), 8)
	if o.BusinessValue > 0 && o.Currency == "" {
		return fmt.Errorf("journey observation %s: a business value needs a currency", o.ID)
	}
	return o.Provenance.Validate()
}

// StepHealth is one step's measured window.
type StepHealth struct {
	StepID   string `json:"step_id"`
	Label    string `json:"label"`
	Optional bool   `json:"optional,omitempty"`
	TargetID string `json:"target_id,omitempty"`

	// Measured is the honesty flag. When false everything below is meaningless
	// and Reason/Detail carry the sentence the UI must render.
	Measured bool   `json:"measured"`
	Reason   string `json:"reason,omitempty"`
	Detail   string `json:"detail,omitempty"`

	SuccessPct float64 `json:"success_pct,omitempty"`
	Samples    int     `json:"samples,omitempty"`
	P95Ms      float64 `json:"p95_ms,omitempty"`
	SLOSuccess float64 `json:"slo_success_pct,omitempty"`
	SLOLatency float64 `json:"slo_latency_ms,omitempty"`
	MeetsSLO   bool    `json:"meets_slo"`
	// Failing marks the step the journey breaks at — the first non-optional
	// measured step that misses its objective, in graph order.
	Failing bool `json:"failing,omitempty"`
}

// JourneyHealth is the journey's measured state over one window.
type JourneyHealth struct {
	JourneyID  string `json:"journey_id"`
	Name       string `json:"name"`
	App        string `json:"app,omitempty"`
	Importance string `json:"business_importance"`
	Window     string `json:"window"`
	Version    int    `json:"version"`

	Measured bool   `json:"measured"`
	Reason   string `json:"reason,omitempty"`
	Detail   string `json:"detail,omitempty"`

	// SuccessPct is the journey's success rate: the product of its REQUIRED
	// measured steps' success ratios. A journey succeeds only if every required
	// step does, so the product — not the mean — is the honest composition. The
	// mean would show a journey with one dead step as "83% healthy".
	SuccessPct float64 `json:"success_pct,omitempty"`
	// StepsMeasured / StepsDeclared expose the coverage behind the number.
	StepsMeasured int `json:"steps_measured"`
	StepsDeclared int `json:"steps_declared"`

	SLO      ExperienceSLO `json:"slo"`
	MeetsSLO bool          `json:"meets_slo"`
	// FailingStepID names where the journey breaks, "" when it does not.
	FailingStepID string       `json:"failing_step_id,omitempty"`
	Steps         []StepHealth `json:"steps"`

	// BusinessImpact is value NOT realised over the window: the declared value
	// per success × the successes the SLO expected but did not happen. Absent
	// unless the operator declared a value.
	BusinessImpact         *float64 `json:"business_impact,omitempty"`
	BusinessImpactCurrency string   `json:"business_impact_currency,omitempty"`
}

// StepMeasurement is what a journey step's bound target measured over the
// window. It is deliberately a small, source-agnostic struct rather than
// internal/dem.Result: this package must not depend on how the measurement was
// produced, only on what it says.
type StepMeasurement struct {
	Measured   bool
	Reason     string
	Detail     string
	Samples    int
	SuccessPct float64
	P95Ms      float64
}

// ComputeJourneyHealth folds per-step measurements into the journey's health.
// PURE.
//
// Rules that are load-bearing rather than stylistic:
//   - a step with no bound target is NOT MEASURED, never "fine";
//   - an unmeasured required step makes the journey's success rate a partial
//     claim, and the response says how many of how many steps it rests on;
//   - success composes MULTIPLICATIVELY over required steps;
//   - optional steps are measured and shown but never gate the journey.
func ComputeJourneyHealth(def JourneyDefinition, window string, m map[string]StepMeasurement) JourneyHealth {
	h := JourneyHealth{
		JourneyID: def.ID, Name: def.Name, App: def.App,
		Importance: def.BusinessImportance, Window: window, Version: def.Version,
		SLO: def.SLO, StepsDeclared: len(def.Steps), Steps: make([]StepHealth, 0, len(def.Steps)),
	}
	product := 1.0
	measuredRequired := 0
	for _, s := range def.Steps {
		sh := StepHealth{StepID: s.ID, Label: s.Label, Optional: s.Optional, TargetID: s.TargetID,
			SLOSuccess: s.SLOSuccessPct, SLOLatency: s.SLOLatencyMs}
		if sh.SLOSuccess == 0 {
			sh.SLOSuccess = def.SLO.SuccessPct
		}
		if sh.SLOLatency == 0 {
			sh.SLOLatency = def.SLO.LatencyMs
		}
		switch meas, ok := m[s.ID]; {
		case s.TargetID == "":
			sh.Reason = ReasonStepUnbound
			sh.Detail = "this step is declared but bound to no measurement, so nothing observes it"
		case !ok:
			sh.Reason = ReasonStepNoMeasurement
			sh.Detail = "the target bound to this step reported nothing in this window"
		case !meas.Measured:
			sh.Reason = meas.Reason
			sh.Detail = meas.Detail
		default:
			sh.Measured = true
			sh.SuccessPct = round2(meas.SuccessPct)
			sh.Samples = meas.Samples
			sh.P95Ms = round2(meas.P95Ms)
			sh.MeetsSLO = (sh.SLOSuccess == 0 || sh.SuccessPct >= sh.SLOSuccess) &&
				(sh.SLOLatency == 0 || sh.P95Ms <= sh.SLOLatency)
			if !s.Optional {
				product *= clamp01(sh.SuccessPct / 100)
				measuredRequired++
			}
			if !sh.MeetsSLO && !s.Optional && h.FailingStepID == "" {
				sh.Failing = true
				h.FailingStepID = s.ID
			}
		}
		if sh.Measured {
			h.StepsMeasured++
		}
		h.Steps = append(h.Steps, sh)
	}
	if measuredRequired == 0 {
		h.Reason = ReasonJourneyNotMeasured
		h.Detail = "no required step of this journey is measured, so it has no success rate — this is an absent result, not a healthy one"
		return h
	}
	h.Measured = true
	h.SuccessPct = round2(product * 100)
	h.MeetsSLO = !def.SLO.Declared() || h.SuccessPct >= def.SLO.SuccessPct
	if def.BusinessValuePerSuccess > 0 && def.SLO.Declared() {
		// Value not realised = the shortfall against the objective, applied to
		// the traversals we actually observed. It is deliberately conservative:
		// it never extrapolates to traffic we did not measure.
		shortfall := (def.SLO.SuccessPct - h.SuccessPct) / 100
		if shortfall < 0 {
			shortfall = 0
		}
		samples := 0
		for _, s := range h.Steps {
			if s.Measured && s.Samples > samples {
				samples = s.Samples
			}
		}
		v := round2(shortfall * float64(samples) * def.BusinessValuePerSuccess)
		h.BusinessImpact = &v
		h.BusinessImpactCurrency = def.Currency
	}
	return h
}

// Journey not-measured reason codes. They join internal/dem's vocabulary rather
// than inventing a parallel one; these three are the ones only a journey has.
const (
	ReasonStepUnbound        = "step_not_bound"
	ReasonStepNoMeasurement  = "step_no_measurement"
	ReasonJourneyNotMeasured = "journey_not_measured"
	ReasonNoJourneys         = "no_journeys"
)

// SortJourneyHealth orders journeys for triage: failing first, then by business
// importance, then worst success rate, then name. Deterministic throughout.
func SortJourneyHealth(list []JourneyHealth) {
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		af, bf := a.Measured && !a.MeetsSLO, b.Measured && !b.MeetsSLO
		if af != bf {
			return af
		}
		if wa, wb := ImportanceWeight(a.Importance), ImportanceWeight(b.Importance); wa != wb {
			return wa > wb
		}
		if a.Measured && b.Measured && a.SuccessPct != b.SuccessPct {
			return a.SuccessPct < b.SuccessPct
		}
		return a.Name < b.Name
	})
}

// labelSafe bounds an id/label to the characters a metric label, a URL segment
// and a JSON key can all carry.
func labelSafe(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.', r == ' ':
			return r
		default:
			return -1
		}
	}, s)
	return clip(strings.TrimSpace(s), MaxLabelBytes)
}

func nonNegative(v float64) float64 {
	if v < 0 {
		return 0
	}
	return v
}
