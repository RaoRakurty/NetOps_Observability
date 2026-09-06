package compliancemodel

import (
	"sort"

	"netops/backend/internal/secfindings"
)

// standardCaption is the §5d defensible-claim caption attached to every
// per-framework view: Correlix reports control EVIDENCE for the technical slice a
// config audit can reach, NEVER "certified" framework compliance.
//
// The 2026-09-06 word sweep (tracker 270) cut it to the claim itself; the two
// sentences that explained the claim are ai/skills/explain/compliance.not-certified.md,
// reachable from the `(i)` beside the score. The CLAIM is unchanged — a screen
// states it, and Iris explains it when asked.
const standardCaption = "Evidence, not certification."

// ControlResult is one canonical control's outcome WITHIN a single framework
// projection: whether Correlix has a check for it (coverage), the worst verdict
// the run's findings produced for it (assessment), and the framework requirements
// it satisfies.
type ControlResult struct {
	ControlID    string                 `json:"control_id"`
	Family       string                 `json:"family,omitempty"`
	Title        string                 `json:"title,omitempty"`
	HasCheck     bool                   `json:"has_check"`              // an owned check maps to this control (coverage)
	StatusID     secfindings.StatusID   `json:"status_id"`              // worst verdict from findings; Unknown = unassessed this run
	Status       string                 `json:"status"`                 // StatusID.String()
	Findings     int                    `json:"findings"`               // findings projected onto this control
	Requirements []FrameworkRequirement `json:"requirements,omitempty"` // what this control satisfies in the framework
}

// FrameworkCoverage is the INDEPENDENT per-framework scorecard: coverage % (what
// fraction of the framework's in-scope controls Correlix can evidence) and a
// pass/fail rollup, computed by projecting the shared findings onto THIS
// framework's controls only. Two frameworks over the same findings yield two
// independent FrameworkCoverage values — the basis of per-framework independence.
type FrameworkCoverage struct {
	Framework         string               `json:"framework"`
	Version           string               `json:"version"`
	ControlsInScope   int                  `json:"controls_in_scope"`   // coverage denominator
	ControlsWithCheck int                  `json:"controls_with_check"` // coverage numerator
	CoveragePercent   float64              `json:"coverage_percent"`    // 100 * withCheck / inScope
	Assessed          int                  `json:"assessed"`            // in-scope controls with ≥1 finding this run
	Passed            int                  `json:"passed"`
	Warned            int                  `json:"warned"`
	Failed            int                  `json:"failed"`
	Unassessed        int                  `json:"unassessed"` // in-scope controls with a check but no finding
	Verdict           secfindings.StatusID `json:"verdict_id"` // worst assessed control status; Unknown = nothing assessed
	VerdictName       string               `json:"verdict"`
	// ScorePercent is 100 * Passed / (Passed+Warned+Failed) over the controls
	// that were actually ASSESSED. It is a POINTER so "nothing was assessed"
	// serializes as null and can never be rendered as 0 % (which reads as a
	// total failure) or 100 % (which reads as a clean bill) — the §5g rule that
	// an unassessed control is unknown, never a pass.
	ScorePercent *float64        `json:"score_percent"`
	Controls     []ControlResult `json:"controls"` // per in-scope control, sorted by id
	Caption      string          `json:"caption"`  // the §5d honesty caption
	// Note is the honest empty-state sentence when nothing in this framework's
	// scope was assessed. Empty when there is a score to report.
	Note string `json:"note,omitempty"`
}

// unassessedNote is what a framework with no assessed control says. It is a
// SENTENCE, not a percentage, because there is no honest number: enabling PCI
// on an estate whose findings all map to controls PCI does not cover must read
// as "nothing here speaks to PCI yet", never as 0 %.
const unassessedNote = "No assessed control maps to this framework yet — this is an absence of assessment, not a passing or failing result."

// notInstalledNote is what an enabled framework whose CROSSWALK is not part of
// this deployment says. It deliberately mirrors unassessedNote rather than
// returning nothing: a framework that silently disappears from the page reads
// as "we looked and found nothing to say", which is a lie about a framework
// nothing looked at. Nothing is hidden or deleted — the selection is still the
// tenant's, and the sentence says what would make it scorable.
const notInstalledNote = "This framework's crosswalk is not included in this deployment — no control has been projected onto it. " +
	"The selection is kept and nothing has been hidden; adding the compliance frameworks beyond the default two to this deployment's licence starts scoring it."

// NotLicensedCoverage is the honest non-scorecard for a framework the tenant
// enabled but whose crosswalk this deployment does not carry (see pack.go).
//
// Every number is the "nothing was assessed" value the rest of this file uses
// for that state — a NULL score, an Unknown verdict, an empty control list —
// so no client can read it as a pass, a failure, or a 0 %.
func NotLicensedCoverage(info FrameworkInfo) FrameworkCoverage {
	return FrameworkCoverage{
		Framework:   info.Name,
		Version:     info.Version,
		Verdict:     secfindings.StatusUnknown,
		VerdictName: secfindings.StatusUnknown.String(),
		Controls:    []ControlResult{},
		Caption:     standardCaption,
		Note:        notInstalledNote,
	}
}

// worstRank orders verdicts so a rollup keeps the most severe. Fail dominates,
// then Error, Warning, Pass, NotApplicable; Unknown (no verdict) is lowest so it
// never overrides a real verdict.
func worstRank(s secfindings.StatusID) int {
	switch s {
	case secfindings.StatusFail:
		return 5
	case secfindings.StatusError:
		return 4
	case secfindings.StatusWarning:
		return 3
	case secfindings.StatusPass:
		return 2
	case secfindings.StatusNotApplicable:
		return 1
	default: // StatusUnknown
		return 0
	}
}

// ProjectFramework projects a SHARED set of findings onto ONE selected framework
// and computes that framework's coverage % and pass/fail rollup INDEPENDENTLY.
// This is the core of §5d per-framework independence: the checks run ONCE (the
// findings are the input), and each framework is scored by projecting those same
// findings onto its own in-scope controls via the owned mapping. A finding
// contributes to a framework ONLY when its check maps to a control the framework
// has in scope — so enabling HIPAA vs PCI yields different, independent verdicts
// from identical findings.
//
// per-tenant SELECTABILITY is expressed here purely as the caller's CHOICE of
// which provider(s) to pass — no HTTP/tenant plumbing in this package.
func ProjectFramework(findings []secfindings.Finding, cat *Catalog, fp FrameworkProvider) FrameworkCoverage {
	scope := fp.ControlsInScope()
	inScope := make(map[string]bool, len(scope))
	for _, id := range scope {
		inScope[id] = true
	}

	// Accumulate the worst verdict + finding count per in-scope control by
	// projecting each finding through the check→control mapping, keeping only
	// controls this framework has in scope.
	type acc struct {
		worst secfindings.StatusID
		count int
	}
	byControl := make(map[string]*acc, len(scope))
	for _, f := range findings {
		for _, controlID := range controlsForFinding(cat, f) {
			if !inScope[controlID] {
				continue // out of THIS framework's scope — the independence boundary
			}
			a := byControl[controlID]
			if a == nil {
				a = &acc{worst: secfindings.StatusUnknown}
				byControl[controlID] = a
			}
			a.count++
			if worstRank(f.StatusID) > worstRank(a.worst) {
				a.worst = f.StatusID
			}
		}
	}

	cov := FrameworkCoverage{
		Framework: fp.Framework(),
		Version:   fp.Version(),
		Caption:   standardCaption,
		Verdict:   secfindings.StatusUnknown,
	}
	results := make([]ControlResult, 0, len(scope))
	for _, id := range scope {
		hasCheck := cat.HasCheckForControl(id)
		res := ControlResult{
			ControlID:    id,
			HasCheck:     hasCheck,
			StatusID:     secfindings.StatusUnknown,
			Status:       secfindings.StatusUnknown.String(),
			Requirements: fp.RequirementsFor(id),
		}
		if ctrl, ok := cat.Control(id); ok {
			res.Family = ctrl.Family
			res.Title = ctrl.Title
		}

		cov.ControlsInScope++
		if hasCheck {
			cov.ControlsWithCheck++
		}

		if a := byControl[id]; a != nil {
			res.Findings = a.count
			res.StatusID = a.worst
			res.Status = a.worst.String()
			cov.Assessed++
			switch a.worst {
			case secfindings.StatusFail:
				cov.Failed++
			case secfindings.StatusWarning:
				cov.Warned++
			case secfindings.StatusPass:
				cov.Passed++
			}
			if worstRank(a.worst) > worstRank(cov.Verdict) {
				cov.Verdict = a.worst
			}
		} else if hasCheck {
			// A control Correlix CAN evidence but no finding touched this run.
			cov.Unassessed++
		}
		results = append(results, res)
	}

	sort.Slice(results, func(i, j int) bool { return results[i].ControlID < results[j].ControlID })
	cov.Controls = results
	if cov.ControlsInScope > 0 {
		cov.CoveragePercent = 100 * float64(cov.ControlsWithCheck) / float64(cov.ControlsInScope)
	}
	cov.VerdictName = cov.Verdict.String()
	if scored := cov.Passed + cov.Warned + cov.Failed; scored > 0 {
		pct := 100 * float64(cov.Passed) / float64(scored)
		cov.ScorePercent = &pct
	} else {
		cov.Note = unassessedNote
	}
	return cov
}

// controlsForFinding resolves the canonical 800-53 control ids one finding
// evidences, and is the ONE place that decision is made.
//
// The OWNED check→control mapping wins: it is Correlix IP, it is version-pinned
// (CatalogVersion) and it can express the M:N case a single stamped field
// cannot. A finding whose check has no mapping falls back to the control the
// PRODUCER stamped on it — which is how the hardening catalogue's rules reach a
// framework at all without this package importing that catalogue (a caller that
// wants the mapping treated as owned composes it in via Catalog.With).
//
// A finding with neither maps to NOTHING and contributes to no framework. That
// is deliberate: attributing an unmapped verdict to a framework would be
// inventing evidence.
func controlsForFinding(cat *Catalog, f secfindings.Finding) []string {
	return cat.ControlsForFinding(f)
}

// ControlsForFinding is controlsForFinding as public API: a caller outside this
// package (a handler counting how many findings reached ANY enabled framework)
// must resolve a finding to controls exactly the way the projection does, or the
// count under the cards disagrees with the cards.
func (cat *Catalog) ControlsForFinding(f secfindings.Finding) []string {
	if refs := cat.ControlsForCheck(f.RawRuleID); len(refs) > 0 {
		out := make([]string, 0, len(refs))
		for _, r := range refs {
			out = append(out, r.ControlID)
		}
		return out
	}
	if f.ControlID != "" {
		return []string{f.ControlID}
	}
	return nil
}

// ProjectFrameworks scores EACH selected framework independently from the SAME
// shared findings (§5d "run the check ONCE, project onto each enabled framework
// independently"). The findings are evaluated once by the caller; this projects
// them onto every enabled framework's own scope, returning one independent
// FrameworkCoverage per provider, in the order given. A tenant that enables only
// one framework simply passes only that provider — nobody is forced to see all.
func ProjectFrameworks(findings []secfindings.Finding, cat *Catalog, fps []FrameworkProvider) []FrameworkCoverage {
	if len(fps) == 0 {
		return nil
	}
	out := make([]FrameworkCoverage, 0, len(fps))
	for _, fp := range fps {
		out = append(out, ProjectFramework(findings, cat, fp))
	}
	return out
}

// ProjectSelection is the whole per-tenant compliance answer in one call: it
// resolves an enabled SELECTION of framework ids through the core catalogue
// plus the installed crosswalk packs, projects the shared findings onto each
// resolved framework, and appends an honest not-installed row for every enabled
// framework whose crosswalk this deployment does not carry.
//
// Callers use this rather than ProvidersFor + ProjectFrameworks so the missing
// case cannot be forgotten at one call site and remembered at another. With
// every crosswalk installed it is exactly ProjectFrameworks over ProvidersFor —
// same rows, same order.
func ProjectSelection(findings []secfindings.Finding, cat *Catalog, ids []string, packs ...FrameworkPack) []FrameworkCoverage {
	out := ProjectFrameworks(findings, cat, ProvidersFor(ids, packs...))
	for _, info := range MissingCrosswalks(ids, packs...) {
		out = append(out, NotLicensedCoverage(info))
	}
	return out
}
