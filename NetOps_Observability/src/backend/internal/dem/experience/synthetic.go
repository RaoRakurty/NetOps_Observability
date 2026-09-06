package experience

// synthetic.go — SLICE 5 CONTRACTS: SyntheticDefinition, SyntheticRun with its
// reliability fields, and the COVERAGE MODEL.
//
// The owner's Phase H is explicit that a list of tests is not a coverage model:
// the question is not "which tests exist" but "which real user actions are
// protected, which are not, and which tests cannot be trusted". So:
//
//	Coverage  — per journey STEP (the closest thing Correlix has to a "real
//	            user action" today): how many synthetics protect it, when one
//	            last succeeded, and whether it is protected at all.
//	Reliability— a synthetic that flaps is not evidence. A flaky check must NOT
//	            create a high-severity incident, and [SyntheticReliability]
//	            is what the incident detector consults to refuse to.
//
// NO BROWSER RUNNER IS FAKED. The BROWSER and JOURNEY kinds are declared as
// contracts with no executor; anything that would need one reports honestly
// that no runner exists. Building the type is a promise about the schema, not
// about the capability.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Synthetic kinds (Phase C.8). The first four are EXECUTED today by
// internal/dem's prober; the rest are contract-only until a runner exists.
const (
	SynHTTP            = "HTTP"
	SynAPI             = "API"
	SynDNS             = "DNS"
	SynTLS             = "TLS"
	SynBrowser         = "BROWSER"
	SynJourney         = "JOURNEY"
	SynNetwork         = "NETWORK"
	SynLargePayload    = "LARGE_PAYLOAD"
	SynDirectionalPath = "DIRECTIONAL_PATH"
)

var knownSyntheticKinds = map[string]bool{
	SynHTTP: true, SynAPI: true, SynDNS: true, SynTLS: true, SynBrowser: true,
	SynJourney: true, SynNetwork: true, SynLargePayload: true, SynDirectionalPath: true,
}

// executableSyntheticKinds are the kinds a runner exists for TODAY. Everything
// else is a declared contract, and a definition of an unexecutable kind is
// accepted but reported as having no runner — never silently never-run.
var executableSyntheticKinds = map[string]bool{
	SynHTTP: true, SynAPI: true, SynDNS: true, SynNetwork: true,
}

// ValidSyntheticKind reports whether k is a declared kind.
func ValidSyntheticKind(k string) bool { return knownSyntheticKinds[k] }

// HasRunner reports whether a kind can actually be executed today.
func HasRunner(k string) bool { return executableSyntheticKinds[k] }

// SyntheticDefinition is a declared check, with its vantages.
type SyntheticDefinition struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Version  int    `json:"version"`

	// TargetID binds the definition to the internal/dem catalogue row that
	// actually runs it, when one does. Empty = declared, not executed.
	TargetID string `json:"target_id,omitempty"`
	// JourneyID / StepID bind it to what it PROTECTS — the join the coverage
	// model is built on.
	JourneyID string `json:"journey_id,omitempty"`
	StepID    string `json:"step_id,omitempty"`

	// Vantages are the observation points. Multiple vantages are what make a
	// synthetic capable of a multi-vantage agreement claim; ONE vantage can
	// never be its own second opinion.
	Vantages []string `json:"vantages,omitempty"`

	App  string `json:"app,omitempty"`
	Site string `json:"site,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Validate normalizes a definition.
func (d *SyntheticDefinition) Validate() error {
	d.ID = clip(strings.TrimSpace(d.ID), MaxIDBytes)
	if d.ID == "" {
		return errors.New("synthetic definition: id is required")
	}
	d.TenantID = strings.ToLower(strings.TrimSpace(d.TenantID))
	d.Name = clip(strings.TrimSpace(d.Name), MaxLabelBytes)
	if d.Name == "" {
		return fmt.Errorf("synthetic definition %s: name is required", d.ID)
	}
	d.Kind = strings.ToUpper(strings.TrimSpace(d.Kind))
	if !ValidSyntheticKind(d.Kind) {
		return fmt.Errorf("synthetic definition %s: unknown kind %q", d.ID, clip(d.Kind, 40))
	}
	d.TargetID = clip(strings.TrimSpace(d.TargetID), MaxIDBytes)
	d.JourneyID = clip(strings.TrimSpace(d.JourneyID), MaxIDBytes)
	d.StepID = labelSafe(d.StepID)
	d.App, d.Site = labelSafe(d.App), labelSafe(d.Site)
	if len(d.Vantages) > MaxListLen {
		return fmt.Errorf("synthetic definition %s: too many vantages", d.ID)
	}
	d.Vantages = dedupIDs(d.Vantages)
	if d.Version <= 0 {
		d.Version = 1
	}
	return nil
}

// Synthetic run outcomes.
const (
	RunSuccess = "success"
	RunFailure = "failure"
	RunError   = "error" // the RUNNER failed, which is not the same as the target failing
	RunSkipped = "skipped"
)

// StepResult is one step of a run.
type StepResult struct {
	StepID     string  `json:"step_id"`
	Outcome    string  `json:"outcome"`
	DurationMs float64 `json:"duration_ms,omitempty"`
	Error      string  `json:"error,omitempty"`
}

// SyntheticRun is ONE immutable execution.
type SyntheticRun struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	DefinitionID string `json:"definition_id"`
	// DefinitionVersion pins the run to the definition AS IT WAS. A test edited
	// after the fact must never appear to have always been what it is now.
	DefinitionVersion int `json:"definition_version"`

	VantageID string    `json:"vantage_id"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`

	Outcome    string       `json:"outcome"`
	FailReason string       `json:"fail_reason,omitempty"`
	Steps      []StepResult `json:"steps,omitempty"`

	DurationMs float64 `json:"duration_ms,omitempty"`
	TTFBMs     float64 `json:"ttfb_ms,omitempty"`
	StatusCode int     `json:"status_code,omitempty"`

	// PathObservationID joins the run to the path it rode. ArtifactRef is a
	// POINTER to a screenshot/HAR held by whatever stores artifacts — never the
	// artifact itself, which is how a run record stays small and how a
	// screenshot never lands in a JSON API response.
	PathObservationID string `json:"path_observation_id,omitempty"`
	ArtifactRef       string `json:"artifact_ref,omitempty"`
	SessionRef        string `json:"session_ref,omitempty"`

	// ── reliability inputs (slice 5) ──
	// Retries is how many attempts the runner made before recording this
	// outcome; a check that only passes on retry is not a healthy check.
	Retries int `json:"retries,omitempty"`
	// RunnerVersion and SelectorStable exist so selector churn (a browser
	// runner's classic flakiness source) is recordable the day a runner lands.
	RunnerVersion  string `json:"runner_version,omitempty"`
	SelectorStable *bool  `json:"selector_stable,omitempty"`

	Provenance `json:"provenance"`
}

// Validate refuses a run that contradicts itself.
func (r *SyntheticRun) Validate() error {
	r.ID = clip(strings.TrimSpace(r.ID), MaxIDBytes)
	if r.ID == "" {
		return errors.New("synthetic run: id is required")
	}
	r.TenantID = strings.ToLower(strings.TrimSpace(r.TenantID))
	r.DefinitionID = clip(strings.TrimSpace(r.DefinitionID), MaxIDBytes)
	if r.DefinitionID == "" {
		return fmt.Errorf("synthetic run %s: definition_id is required", r.ID)
	}
	if r.DefinitionVersion <= 0 {
		r.DefinitionVersion = 1
	}
	r.VantageID = clip(strings.TrimSpace(r.VantageID), MaxIDBytes)
	if r.VantageID == "" {
		return fmt.Errorf("synthetic run %s: vantage_id is required (a measurement with no vantage cannot be an independent observation)", r.ID)
	}
	switch r.Outcome {
	case RunSuccess, RunFailure, RunError, RunSkipped:
	default:
		return fmt.Errorf("synthetic run %s: outcome must be success|failure|error|skipped", r.ID)
	}
	if r.Outcome == RunSuccess && r.FailReason != "" {
		return fmt.Errorf("synthetic run %s: a successful run cannot carry a fail reason", r.ID)
	}
	if r.StartedAt.IsZero() {
		return fmt.Errorf("synthetic run %s: started_at is required", r.ID)
	}
	if !r.EndedAt.IsZero() && r.EndedAt.Before(r.StartedAt) {
		return fmt.Errorf("synthetic run %s: ended_at precedes started_at", r.ID)
	}
	if r.Retries < 0 {
		return fmt.Errorf("synthetic run %s: retries must not be negative", r.ID)
	}
	r.DurationMs, r.TTFBMs = nonNegative(r.DurationMs), nonNegative(r.TTFBMs)
	if len(r.Steps) > MaxListLen {
		return fmt.Errorf("synthetic run %s: too many step results", r.ID)
	}
	return r.Provenance.Validate()
}

// Reliability grades, worst to best.
const (
	ReliabilitySolid   = "solid"
	ReliabilityNoisy   = "noisy"
	ReliabilityFlaky   = "flaky"
	ReliabilityBroken  = "broken"
	ReliabilityUnknown = "unknown"
)

// SyntheticReliability grades whether a check's RESULTS can be trusted.
type SyntheticReliability struct {
	DefinitionID string  `json:"definition_id"`
	Grade        string  `json:"grade"`
	Score        float64 `json:"score"` // 0..1; 1 = fully trustworthy
	Reason       string  `json:"reason"`

	Runs         int `json:"runs"`
	Failures     int `json:"failures"`
	Flips        int `json:"flips"`         // success→failure→success transitions
	RunnerErrors int `json:"runner_errors"` // the runner broke, not the target
	RetriedRuns  int `json:"retried_runs"`
	Vantages     int `json:"vantages"`
	// DisagreeingVantages is how many vantages disagreed with the majority in
	// the same round. Vantage-specific failure is the signature of a LOCAL
	// problem — or of one broken prober.
	DisagreeingVantages int `json:"disagreeing_vantages"`
}

// MinRunsForReliability is the sample floor below which reliability is UNKNOWN
// rather than guessed. Three runs cannot tell a flaky check from an outage.
const MinRunsForReliability = 10

// FlakyFlipRatio is the flip-per-run ratio at which a check is called flaky.
// A check that changes its mind on a fifth of its runs is not measuring
// anything stable enough to page a human about.
const FlakyFlipRatio = 0.2

// GradeReliability grades a definition from its runs, newest LAST. PURE.
//
// It exists to answer exactly one operational question: may this check's
// failure raise a high-severity incident on its own? [SyntheticReliability.Trustworthy]
// is what the incident detector asks, and a flaky check answers no.
func GradeReliability(defID string, runs []SyntheticRun) SyntheticReliability {
	out := SyntheticReliability{DefinitionID: defID, Runs: len(runs), Grade: ReliabilityUnknown, Score: 0}
	if len(runs) == 0 {
		out.Reason = "no run has been recorded, so nothing is known about this check's reliability"
		return out
	}
	vantages := map[string]bool{}
	prev := ""
	for _, r := range runs {
		vantages[r.VantageID] = true
		if r.Retries > 0 {
			out.RetriedRuns++
		}
		switch r.Outcome {
		case RunFailure:
			out.Failures++
		case RunError:
			out.RunnerErrors++
		}
		cur := r.Outcome
		if prev != "" && cur != prev && (cur == RunSuccess || prev == RunSuccess) {
			out.Flips++
		}
		prev = cur
	}
	out.Vantages = len(vantages)
	if len(runs) < MinRunsForReliability {
		out.Reason = "too few runs to tell a flaky check from a real failure — " +
			plural(len(runs), "run", "runs") + " recorded, " + plural(MinRunsForReliability, "run is", "runs are") + " needed"
		return out
	}

	flipRatio := float64(out.Flips) / float64(len(runs))
	errRatio := float64(out.RunnerErrors) / float64(len(runs))
	retryRatio := float64(out.RetriedRuns) / float64(len(runs))
	score := clamp01(1 - flipRatio*2 - errRatio*1.5 - retryRatio*0.5)
	out.Score = round2(score)
	switch {
	case errRatio >= 0.5:
		out.Grade = ReliabilityBroken
		out.Reason = "the runner itself failed on most attempts, so this check is not measuring the service at all"
	case flipRatio >= FlakyFlipRatio:
		out.Grade = ReliabilityFlaky
		out.Reason = "the result changed on " + plural(out.Flips, "run", "runs") +
			" out of " + plural(len(runs), "run", "runs") + " — a check that changes its mind this often cannot raise a high-severity incident on its own"
	case flipRatio > 0 || retryRatio > 0.2:
		out.Grade = ReliabilityNoisy
		out.Reason = "occasional flips or retries; usable as corroboration, weaker on its own"
	default:
		out.Grade = ReliabilitySolid
		out.Reason = "consistent results across its runs"
	}
	return out
}

// Trustworthy reports whether this check's failure may, by itself, raise a
// high-severity experience incident. A flaky, broken or unknown check may not.
func (r SyntheticReliability) Trustworthy() bool {
	return r.Grade == ReliabilitySolid || r.Grade == ReliabilityNoisy
}

// Coverage states for one protected action.
const (
	CoverageProtected = "protected"
	CoverageThin      = "thin"     // exactly one synthetic, or one vantage
	CoverageUntested  = "untested" // nothing measures it
	CoverageBroken    = "broken"   // synthetics exist but none of them can be trusted
	CoverageStale     = "stale"    // nothing has succeeded recently enough to count
)

// ActionCoverage is one real user action's protection.
type ActionCoverage struct {
	JourneyID  string `json:"journey_id"`
	StepID     string `json:"step_id"`
	Label      string `json:"label"`
	App        string `json:"app,omitempty"`
	Importance string `json:"business_importance"`

	// InteractionVolume is how often people actually do this. Nil = we do not
	// know (no RUM), which is stated rather than assumed to be zero — an action
	// nobody measures is not an action nobody performs.
	InteractionVolume *int `json:"interaction_volume,omitempty"`

	Synthetics       int        `json:"synthetics"`
	Vantages         int        `json:"vantages"`
	LastSuccess      *time.Time `json:"last_success,omitempty"`
	ReliabilityGrade string     `json:"reliability_grade"`

	State  string `json:"state"`
	Detail string `json:"detail"`
}

// CoverageReport is the whole coverage model for one tenant.
type CoverageReport struct {
	Window  string           `json:"window"`
	Actions []ActionCoverage `json:"actions"`

	Critical  int `json:"critical_actions"`
	Protected int `json:"protected_actions"`
	Untested  int `json:"untested_actions"`
	Thin      int `json:"thin_actions"`
	Broken    int `json:"broken_tests"`
	Flaky     int `json:"flaky_tests"`

	// CoveragePct is protected / total, as a percentage. Nil when there is
	// nothing to cover — 100% coverage of zero actions is not a fact worth
	// rendering as a success.
	CoveragePct *float64 `json:"coverage_pct,omitempty"`
	Detail      string   `json:"detail"`
}

// BuildCoverage folds journeys, their synthetics and those synthetics'
// reliability into the coverage model. PURE.
func BuildCoverage(window string, journeys []JourneyDefinition,
	defsByStep map[string][]SyntheticDefinition,
	reliability map[string]SyntheticReliability,
	lastSuccess map[string]time.Time) CoverageReport {

	rep := CoverageReport{Window: window, Actions: []ActionCoverage{}}
	for _, j := range journeys {
		for _, s := range j.Steps {
			key := j.ID + "/" + s.ID
			defs := defsByStep[key]
			a := ActionCoverage{
				JourneyID: j.ID, StepID: s.ID, Label: s.Label, App: j.App,
				Importance: j.BusinessImportance, Synthetics: len(defs),
				ReliabilityGrade: ReliabilityUnknown,
			}
			vantages := map[string]bool{}
			worst := ReliabilitySolid
			anyTrustworthy := false
			for _, d := range defs {
				for _, v := range d.Vantages {
					vantages[v] = true
				}
				if len(d.Vantages) == 0 {
					vantages["default"] = true
				}
				// An UNGRADED check counts as `unknown`, never as `solid`.
				// The map is keyed by definition id and a definition with no
				// run history is simply absent from it; folding that absence
				// into the best possible grade is exactly the "a check nobody
				// graded is a check that passed" lie this model exists to
				// refuse (tracker 253).
				grade := ReliabilityUnknown
				if r, ok := reliability[d.ID]; ok {
					grade = r.Grade
					if r.Trustworthy() {
						anyTrustworthy = true
					}
					if r.Grade == ReliabilityFlaky {
						rep.Flaky++
					}
					if r.Grade == ReliabilityBroken {
						rep.Broken++
					}
				}
				if reliabilityRank(grade) > reliabilityRank(worst) {
					worst = grade
				}
				if ts, ok := lastSuccess[d.ID]; ok {
					if a.LastSuccess == nil || ts.After(*a.LastSuccess) {
						t := ts
						a.LastSuccess = &t
					}
				}
			}
			a.Vantages = len(vantages)
			if len(defs) > 0 {
				a.ReliabilityGrade = worst
			}
			switch {
			case len(defs) == 0:
				a.State = CoverageUntested
				a.Detail = "nothing measures this step, so its health is unknown — not good"
				rep.Untested++
			case !anyTrustworthy && worst == ReliabilityBroken:
				a.State = CoverageBroken
				a.Detail = "the checks that protect this step are not running correctly, so it is effectively untested"
				rep.Untested++
			case a.LastSuccess == nil:
				a.State = CoverageStale
				a.Detail = "no check protecting this step has succeeded, so we cannot say it works"
			case a.Vantages < 2:
				a.State = CoverageThin
				a.Detail = "protected from a single vantage — enough to notice a failure, not enough to confirm one, because one vantage cannot be its own second opinion"
				rep.Thin++
				rep.Protected++
			default:
				a.State = CoverageProtected
				a.Detail = "protected by " + plural(len(defs), "check", "checks") + " from " + plural(a.Vantages, "vantage", "vantages")
				rep.Protected++
			}
			if j.BusinessImportance == ImportanceCritical {
				rep.Critical++
			}
			rep.Actions = append(rep.Actions, a)
		}
	}
	total := len(rep.Actions)
	if total > 0 {
		p := round2(float64(rep.Protected) / float64(total) * 100)
		rep.CoveragePct = &p
		rep.Detail = plural(rep.Protected, "action is", "actions are") + " protected out of " +
			plural(total, "declared action", "declared actions") + "."
	} else {
		rep.Detail = "No journey step is declared, so there is nothing to have coverage of. This is not 100% coverage."
	}
	sort.SliceStable(rep.Actions, func(i, j int) bool {
		a, b := rep.Actions[i], rep.Actions[j]
		if wa, wb := coverageRank(a.State), coverageRank(b.State); wa != wb {
			return wa > wb
		}
		if ia, ib := ImportanceWeight(a.Importance), ImportanceWeight(b.Importance); ia != ib {
			return ia > ib
		}
		return a.JourneyID+a.StepID < b.JourneyID+b.StepID
	})
	return rep
}

func reliabilityRank(g string) int {
	switch g {
	case ReliabilityBroken:
		return 4
	case ReliabilityFlaky:
		return 3
	case ReliabilityNoisy:
		return 2
	case ReliabilityUnknown:
		return 1
	default:
		return 0
	}
}

func coverageRank(s string) int {
	switch s {
	case CoverageUntested:
		return 4
	case CoverageBroken:
		return 3
	case CoverageStale:
		return 2
	case CoverageThin:
		return 1
	default:
		return 0
	}
}

// ── the run source seam and the fleet grade (tracker 253) ───────────────────

// RunSource supplies the immutable per-RUN records a reliability grade is
// computed from. It is a SEAM, not a store: this package never learns where the
// runs came from (a prober's key-value channel today, a browser runner's
// results tomorrow), only that they arrive already scoped to one tenant.
//
// nil is a legal wiring and is HONEST: with no run source every check grades
// `unknown` and the coverage surface says why, rather than calling an ungraded
// check trustworthy.
type RunSource interface {
	// Runs returns ONE tenant's recent runs keyed by definition id, oldest
	// first. There is no cross-tenant read on this seam at all (§3a rule 4):
	// a caller with no concrete tenant gets nothing, never everything.
	Runs(ctx context.Context, tenant string) (map[string][]SyntheticRun, error)
}

// GradeAll grades every definition that has runs. PURE.
//
// A definition with an EMPTY history is left out of the result entirely rather
// than mapped to an `unknown` grade — see the note at its only caller: absent
// and untrustworthy are treated identically by everything downstream, and
// absent is the shape that cannot be misread as "we looked and found nothing
// wrong".
func GradeAll(runs map[string][]SyntheticRun) map[string]SyntheticReliability {
	out := make(map[string]SyntheticReliability, len(runs))
	for defID, list := range runs {
		if len(list) == 0 {
			continue
		}
		out[defID] = GradeReliability(defID, list)
	}
	return out
}

// CoverageReliabilityNote is the sentence the coverage surface prints about the
// grades it is showing. It is derived from the SAME facts the grades are, so
// the note cannot claim a state the numbers contradict.
func CoverageReliabilityNote(configured bool, graded, ungraded int, err error) string {
	switch {
	case err != nil:
		return "Per-check reliability could not be read, so every check below is ungraded. An ungraded check is not a check that passed."
	case !configured:
		return "No source of per-run records is wired, so every check below is ungraded. An ungraded check is not a check that passed."
	case graded == 0 && ungraded == 0:
		return "No check is declared, so there is nothing to grade."
	case graded == 0:
		return "No check has recorded enough runs to be graded yet (" +
			plural(MinRunsForReliability, "run is", "runs are") + " needed). An ungraded check is not a check that passed."
	case ungraded > 0:
		return plural(graded, "check is", "checks are") + " graded from their run history; " +
			plural(ungraded, "is", "are") + " still ungraded. An ungraded check is not a check that passed."
	}
	return plural(graded, "check is", "checks are") + " graded from their own run history."
}
