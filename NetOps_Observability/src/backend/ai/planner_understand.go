// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// Model-first phase 2 (owner 2026-11-13, decision points 3 and 5): the planner
// picks the arm, and the arm must then UNDERSTAND the question however it was
// phrased. Two mechanisms, both server-side and closed:
//
//   - TERMS: the planner may restate the question in Correlix's own words
//     (product terms, metric names, names from the generated vocabulary) on
//     one optional, validated line. An arm whose lexical lookup missed the
//     operator's wording (docs search, feature finder, playbook search, the
//     data grammar, the method matcher) retries once with those words —
//     no extra model call.
//   - No dead ends: a planned arm that still finds nothing hands the question
//     to the grounded model answer where that is honest (a playbook miss, a
//     navigation miss that the docs can answer), instead of a "try naming the
//     area" decline.
//
// IsDeadEnd is the single definition of "the operator got no answer", used by
// the paraphrase dead-end ratchet and by the miss triage.

import (
	"context"
	"regexp"
	"strings"

	"netops/backend/internal/irisglossary"
	"netops/backend/internal/iristriage"
)

// The three honest "nothing matched" answers. Named so the dead-end check and
// the triage read the same strings the arms write.
const (
	NoFeatureMatchText = "I couldn't match that to a Correlix feature. Try naming the area (correlations, topology, reports, integrations, flows, logs, devices)."
	NoPlaybookNote     = "No matching playbook."
	NoDocsNote         = "No matching documentation — nothing was invented."
	// ModuleNotBuiltNote: the module's tools are not available in this
	// deployment (not a permission or licence denial).
	ModuleNotBuiltNote = "This module's AI tools land in a later increment."
)

// moduleNotBuilt reports a module answer that found no tools to run — the one
// module outcome a planned question may hand to the model. A permission or
// enablement denial is never handed on: the denial IS the answer (§3a).
func moduleNotBuilt(ans Answer) bool {
	if ans.Mode != ModeUnavailable {
		return false
	}
	for _, d := range ans.Disclaimers {
		if d == ModuleNotBuiltNote {
			return true
		}
	}
	return false
}

// IsDeadEnd reports an answer that gave the operator nothing to act on: the
// capability decline ("I didn't quite catch that"), a not-available mode, or
// an arm's honest no-match. A grounded answer that says the data does not
// cover the question is NOT a dead end — it named what would answer it.
func IsDeadEnd(ans Answer) bool {
	if ans.Mode == ModeUnavailable {
		return true
	}
	if ans.Mode == ModeProductNavigationHelp && ans.Text == NoFeatureMatchText {
		return true
	}
	for _, d := range ans.Disclaimers {
		if d == NoDocsNote || d == NoPlaybookNote {
			return true
		}
	}
	return false
}

// rePlannerTerms is the optional restatement line: letters, digits and a few
// name characters, at most 80 runes — never markup, never an instruction
// channel (the arms only search with it).
var rePlannerTerms = regexp.MustCompile(`^TERMS:\s*([\p{L}\p{N} ._/&+()'-]{1,80})$`)

// parsePlannerTerms returns the validated restatement of a TERMS line, or ""
// (an address is refused: names in it must be the vocabulary's, never an IP).
func parsePlannerTerms(line string) (string, bool) {
	m := rePlannerTerms.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return "", false
	}
	t := strings.Join(strings.Fields(m[1]), " ")
	if t == "" || irisglossary.HasAddress(t) || len(strings.Fields(t)) > 12 {
		return "", false
	}
	return t, true
}

// glossaryText is the caller's generated vocabulary followed by what is in
// view on their screen (view_binding.go, N-E4) — the fenced context every
// model path reads. "" when neither is available.
func (o *Orchestrator) glossaryText(ctx context.Context, p Principal) string {
	g := ""
	if o.Glossary != nil {
		g = strings.TrimSpace(o.Glossary(ctx, p))
	}
	if v := o.view.block(); v != "" {
		if g != "" {
			g += "\n\n"
		}
		g += v
	}
	return g
}

// readAsNote discloses that an arm searched with the planner's restatement.
func readAsNote(terms string) string {
	return "Read your question as: “" + terms + "” (the AI model's restatement in Correlix terms)."
}

// answerProductPlanned answers a planned product question from the docs: the
// operator's words first, then the planner's restatement. ok=false = neither
// matched (the classic arm then gives the honest decline).
func (o *Orchestrator) answerProductPlanned(question, terms string, uiContext map[string]string) (Answer, bool) {
	if o.Docs == nil {
		return Answer{}, false
	}
	plan, _ := planForRoute(PlanRouteProduct, nil)
	var pageSlugs map[string]bool
	if _, page, ok := pageForContext(uiContext); ok {
		pageSlugs = page.slugSet()
	}
	if a, ok := o.answerProductFromDocs(question, plan, nil, pageSlugs); ok {
		return a, true
	}
	if terms != "" {
		if a, ok := o.answerProductFromDocs(terms, plan, nil, pageSlugs); ok {
			a.Disclaimers = append(a.Disclaimers, readAsNote(terms))
			return a, true
		}
	}
	return Answer{}, false
}

// answerNavigationPlanned finds the feature by the operator's words, then by
// the restatement; a feature the finder cannot place may still be documented.
func (o *Orchestrator) answerNavigationPlanned(question, terms string, uiContext map[string]string) (Answer, bool) {
	plan, _ := planForRoute(PlanRouteNavigation, nil)
	if len(FindFeature(question)) > 0 {
		return o.answerNavigation(question, plan, nil), true
	}
	if terms != "" && len(FindFeature(terms)) > 0 {
		a := o.answerNavigation(terms, plan, nil)
		a.Disclaimers = append(a.Disclaimers, readAsNote(terms))
		return a, true
	}
	return o.answerProductPlanned(question, terms, uiContext)
}

// playbookFor reports whether the curated library (or the vendor TAC
// knowledge) holds guidance for text.
func (o *Orchestrator) playbookFor(text string) bool {
	if text == "" {
		return false
	}
	if o.KB != nil && len(o.KB.Search(text, KBHints{}, 1)) > 0 {
		return true
	}
	return len(o.tacFor(text, 1)) > 0
}

// answerFeature answers with the feature finder when it places the operator's
// words or the restatement; ok=false when it places neither.
func (o *Orchestrator) answerFeature(question, terms string) (Answer, bool) {
	plan, _ := planForRoute(PlanRouteNavigation, nil)
	if len(FindFeature(question)) > 0 {
		return o.answerNavigation(question, plan, nil), true
	}
	if terms != "" && len(FindFeature(terms)) > 0 {
		a := o.answerNavigation(terms, plan, nil)
		a.Disclaimers = append(a.Disclaimers, readAsNote(terms))
		return a, true
	}
	return Answer{}, false
}

// AccessDeniedText is the honest answer to a question the caller may not ask
// (a module they lack permission for, or one not enabled for the tenant).
const AccessDeniedText = "I can't answer that for your current access or enabled modules."

// Disclosures the triage reads (named where the arms write them).
const (
	notBuiltModeText = "That question type isn't available in this build yet."
	moduleIOFailNote = "Module read failed (transient); not a coverage gap."
)

// TriageSignals maps one shipped answer to the miss-triage signals
// (internal/iristriage). The data arm records its own misses in the query log,
// so a data answer carries no dead-end kind here.
func TriageSignals(ans Answer, modelFirst bool) iristriage.Signals {
	s := iristriage.Signals{ModelFirst: modelFirst}
	if ans.Routing != nil && ans.Routing.Reason == RouteReasonPlannerUnavailable {
		s.PlannerUnavailable = true
	}
	has := func(note string) bool {
		for _, d := range ans.Disclaimers {
			if d == note {
				return true
			}
		}
		return false
	}
	switch {
	case ans.Mode == ModeDataQuery:
	case ans.Text == AccessDeniedText:
		s.DeadEndKind = iristriage.EndDenied
	case ans.Mode == ModeUnavailable && ans.Intent == "capability":
		s.DeadEndKind = iristriage.EndCapability
	case has(ModuleNotBuiltNote), ans.Mode == ModeUnavailable && strings.HasPrefix(ans.Text, notBuiltModeText):
		s.DeadEndKind = iristriage.EndNotBuilt
	case has(moduleIOFailNote):
		s.DeadEndKind = iristriage.EndUnavailableIO
	case has(NoPlaybookNote):
		s.DeadEndKind = iristriage.EndNoPlaybook
	case has(NoDocsNote):
		s.DeadEndKind = iristriage.EndNoDocs
	case ans.Mode == ModeProductNavigationHelp && ans.Text == NoFeatureMatchText:
		s.DeadEndKind = iristriage.EndNoFeature
	case ans.Mode == ModeUnavailable:
		s.DeadEndKind = iristriage.EndNotBuilt
	}
	return s
}
