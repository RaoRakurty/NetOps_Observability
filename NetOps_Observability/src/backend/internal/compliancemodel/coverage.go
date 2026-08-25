package compliancemodel

import (
	"sort"

	"netops/backend/internal/secfindings"
)

// standardCaption is the §5d defensible-claim caption attached to every
// per-framework view: Correlix reports control EVIDENCE for the technical slice a
// config audit can reach, NEVER "certified" framework compliance.
const standardCaption = "Audit-ready control evidence mapped to framework controls — not certified compliance. Coverage reflects the technical controls a configuration audit can evidence."

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
	Controls          []ControlResult      `json:"controls"` // per in-scope control, sorted by id
	Caption           string               `json:"caption"`  // the §5d honesty caption
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
		refs := cat.ControlsForCheck(f.RawRuleID)
		for _, r := range refs {
			if !inScope[r.ControlID] {
				continue // out of THIS framework's scope — the independence boundary
			}
			a := byControl[r.ControlID]
			if a == nil {
				a = &acc{worst: secfindings.StatusUnknown}
				byControl[r.ControlID] = a
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
	return cov
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
