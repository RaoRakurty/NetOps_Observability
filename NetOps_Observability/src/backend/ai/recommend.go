// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// recommend.go — recommendation cards (tracker 337 N-I7; Part 1 §27
// RECOMMEND class).
//
// A card is a SUGGESTION, grounded in the evidence the answer cites, and it
// is always labelled "No action has been executed." It never performs
// anything: the type has no href, URL, method, command or action field, and
// the UI renders it as text with no button.
//
// SERVER-AUTHORED ONLY. Cards are built from the answer's NextActions, which
// every producer writes deterministically (NextActionsRCA, the live-state and
// skill decision builders, the playbook sections) — model prose never becomes
// a card (§15 LLM02/LLM08). A card's Basis is a non-empty subset of THIS
// answer's citation ids; a card with no basis is not made (the plain list
// still shows, with the same notice).

import "strings"

// NoActionNotice is the label every card carries.
const NoActionNotice = "No action has been executed."

// Recommendation origins (closed).
const (
	RecFromRCA       = "rca_next_actions"
	RecFromSkill     = "skill_decision"
	RecFromLiveState = "live_state"
	RecFromPlaybook  = "kb_playbook"
)

// Card bounds.
const (
	maxRecSteps     = 6
	maxRecStepChars = 300
	maxRecBasis     = 8
	maxRecTitle     = 120
)

// Recommendation is one card.
type Recommendation struct {
	ID     string   `json:"id"`
	Title  string   `json:"title"`
	Steps  []string `json:"steps"`
	Why    string   `json:"why"`
	Basis  []string `json:"basis"` // citation ids of this answer
	Owner  string   `json:"owner,omitempty"`
	Origin string   `json:"origin"`
	Notice string   `json:"notice"`
}

// recOrigin is which modes recommend, and from what. A product answer's
// "see also" links and the capability prompts are not recommendations.
func recOrigin(m AnswerMode) string {
	switch m {
	case ModeProblemExplanation, ModeTopIncidentExplanation:
		return RecFromRCA
	case ModeTroubleshootFinding:
		return RecFromSkill
	case ModeCurrentStateSummary, ModeNocFocusRecommendation, ModeIncidentStatusBreakdown, ModeShiftHandoff, ModeTimeRangeOutageSummary:
		return RecFromLiveState
	case ModeInvestigationPlan:
		return RecFromPlaybook
	}
	return ""
}

// recBasis picks the citations a card rests on: for a playbook, the
// documentation it came from; otherwise the evidence (navigation links and
// documentation are never evidence for an operational step).
func recBasis(origin string, cites []Citation) []string {
	var out []string
	for _, c := range cites {
		id := strings.TrimSpace(c.ID)
		if id == "" || c.Kind == "navigation" || strings.HasPrefix(id, "nav:") {
			continue // a link into the UI is never a basis
		}
		// Knowledge (playbooks, TAC issue classes, docs) is what a playbook
		// card rests on — and never the basis of an operational card.
		isDoc := c.Kind == "knowledge" || c.Class == "DOCUMENTATION" ||
			strings.HasPrefix(id, "doc:") || strings.HasPrefix(id, "playbook:") || strings.HasPrefix(id, "tac:")
		if (origin == RecFromPlaybook) != isDoc {
			continue // a playbook rests on its document; every other card on evidence
		}
		out = append(out, id)
		if len(out) == maxRecBasis {
			break
		}
	}
	return out
}

func clipRec(s string, n int) string {
	s = promptLine(s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return strings.TrimSpace(s[:cut]) + " …"
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// RecommendationsFor builds the answer's cards (at most one today: the
// answer's next steps, grounded in its evidence).
func RecommendationsFor(a Answer) []Recommendation {
	origin := recOrigin(a.Mode)
	if origin == "" || len(a.NextActions) == 0 {
		return nil
	}
	basis := recBasis(origin, a.Citations)
	if len(basis) == 0 {
		return nil // ungrounded: no card (the plain list still carries the notice)
	}
	var steps []string
	for _, s := range a.NextActions {
		if s = clipRec(s, maxRecStepChars); s != "" {
			steps = append(steps, s)
		}
		if len(steps) == maxRecSteps {
			break
		}
	}
	if len(steps) == 0 {
		return nil
	}
	title := "Suggested next steps"
	why := "Based on the evidence cited in this answer."
	switch origin {
	case RecFromRCA:
		why = "Based on the incident's root-cause analysis and the evidence cited."
	case RecFromSkill:
		why = "Based on what this investigation found."
	case RecFromLiveState:
		why = "Based on the live incidents cited."
	case RecFromPlaybook:
		title = "Suggested checks"
		why = "From the playbook cited."
	}
	return []Recommendation{{
		ID: "rec-1", Title: clipRec(title, maxRecTitle), Steps: steps, Why: why, Basis: basis,
		Owner: clipRec(a.RecommendedOwner, 80), Origin: origin, Notice: NoActionNotice,
	}}
}
