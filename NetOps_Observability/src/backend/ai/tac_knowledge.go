// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// tac_knowledge.go — vendor TAC knowledge as built-in Iris grounding.
//
// Owner, 2026-09-15: the issue-class taxonomy, the per-vendor checks and their
// bound read-only commands are Iris's knowledge, not a page an administrator
// reads. Iris now retrieves them before answering a troubleshooting question —
// alongside the curated playbooks — and shows the model the relevant classes as
// quoted GENERAL guidance when it explains a problem. The catalogue is curated
// reference data with no tenant content, so no permission is needed to read it.
//
// This package does not import the catalogue: the server injects a
// TACKnowledgeSource (the same seam shape as KB / ProductKB / Docs).

import (
	"fmt"
	"strings"
)

// TACKnowledgeIntent is one check for a class, with the command for the vendor
// the question named when the catalogue binds one.
type TACKnowledgeIntent struct {
	Title    string
	Command  string
	Verified bool // true: run on a real capture; false: documented, not verified here
	Consent  bool // a heavy collection the vendor says needs consent
}

// TACKnowledgeHit is one issue class relevant to a question.
type TACKnowledgeHit struct {
	ClassID   string
	Title     string
	Protocol  string
	Summary   string
	FirstLook string
	Dialect   string
	Intents   []TACKnowledgeIntent
}

// TACKnowledgeSource retrieves TAC knowledge for free text. Implementations must
// be deterministic and must return nothing for an off-topic question.
type TACKnowledgeSource interface {
	Lookup(query string, limit int) []TACKnowledgeHit
}

// maxTACIntentsShown bounds a snippet so the prompt and the answer stay tight.
const maxTACIntentsShown = 5

// Snippet renders a hit as bounded plain text for an answer item or a prompt.
func (h TACKnowledgeHit) Snippet() string {
	var b strings.Builder
	b.WriteString(h.Title)
	if h.Protocol != "" {
		b.WriteString(" (" + h.Protocol + ")")
	}
	if h.FirstLook != "" {
		b.WriteString("\nWhat TAC looks at first: " + oneLineTAC(h.FirstLook))
	}
	if checks := h.checkLines(); len(checks) > 0 {
		b.WriteString("\nChecks: " + strings.Join(checks, "; "))
	}
	return strings.TrimSpace(b.String())
}

func (h TACKnowledgeHit) checkLines() []string {
	var out []string
	for _, in := range h.Intents {
		if len(out) >= maxTACIntentsShown {
			break
		}
		line := in.Title
		if in.Command != "" {
			label := "documented, not verified here"
			if in.Verified {
				label = "verified on a capture"
			}
			line = fmt.Sprintf("%s — `%s` on %s (%s)", in.Title, in.Command, h.Dialect, label)
			if in.Consent {
				line += " — heavy collection, needs consent"
			}
		}
		out = append(out, line)
	}
	return out
}

func oneLineTAC(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// tacFor retrieves TAC knowledge for a question; nil when no source is wired.
func (o *Orchestrator) tacFor(question string, limit int) []TACKnowledgeHit {
	if o.TAC == nil {
		return nil
	}
	return o.TAC.Lookup(question, limit)
}

// tacForProblem keys retrieval on a problem's title, missing evidence and
// devices — the same query shape kbFor uses — bounded to 2.
func (o *Orchestrator) tacForProblem(pr *Problem) []TACKnowledgeHit {
	if o.TAC == nil || pr == nil {
		return nil
	}
	query := pr.Title + " " + strings.Join(pr.MissingEvidence, " ") + " " + strings.Join(pr.Devices, " ")
	return o.TAC.Lookup(query, 2)
}

// answerTACKnowledge answers from TAC knowledge alone. ok=false when nothing
// matched, so the caller keeps its previous path unchanged.
func (o *Orchestrator) answerTACKnowledge(plan Plan, disc []string, hits []TACKnowledgeHit) (Answer, bool) {
	if len(hits) == 0 {
		return Answer{}, false
	}
	top := hits[0]
	mh := &ModuleHealthSummary{Module: "tac_knowledge", DisplayName: "Vendor TAC knowledge"}
	cites := make([]Citation, 0, len(hits))
	for _, h := range hits {
		mh.Items = append(mh.Items, h.Snippet())
		cites = append(cites, Citation{ID: "tac:" + h.ClassID, Kind: "knowledge", Label: h.Title})
	}
	mh.Headline = "What a vendor TAC checks for: " + top.Title + " — general guidance, not live evidence about your network. Verify against Correlix evidence."
	var next []string
	if top.FirstLook != "" {
		next = append(next, "Start where TAC starts: "+oneLineTAC(top.FirstLook))
	}
	next = append(next, top.checkLines()...)
	return Answer{
		Mode: ModeInvestigationPlan, Intent: plan.Intent, Modules: plan.Modules,
		Text: mh.Headline, Module: mh, Citations: cites, NextActions: next,
		ModeBadges:  []string{"Guidance"},
		Disclaimers: append(disc, tacDisclaimer),
	}, true
}

const tacDisclaimer = "Vendor TAC knowledge — general guidance, not evidence; commands run only through Correlix's read-only collection."
