// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// rca_result.go — the Iris-consumable RCA contract (tracker 337 N-B1) and the
// four read tools that expose it (N-B2).
//
// NOT A SECOND RCA ENGINE. Every field is a projection of the correlation
// engine's own report (internal/rca.Report, built by the server through the
// same tenant-scoped read the RCA page uses). Iris explains this object; it
// never recomputes a verdict, a confidence, a causal link, an owner or an
// impact number. The projection is BOUNDED so a whole result fits a prompt.
//
// Relationship provenance (Part 1 §14): every causal link carries both the
// engine's own epistemic state and one of four relation classes, so an
// inferred link can never be narrated as an observed one:
//
//	OBSERVED     — the step's evidence was directly observed (observed |
//	               corroborated in the engine's vocabulary)
//	INFERRED     — the engine inferred the step; it was not directly observed
//	               (inferred | contradicted | unknown)
//	DERIVED      — computed from other observations by deterministic code
//	               (reserved; the engine does not emit it today)
//	USER_DEFINED — reported by a person or an external party (reported)

import (
	"context"
	"fmt"
	"strings"
)

// Relation classes for a causal link.
const (
	RelationObserved    = "OBSERVED"
	RelationInferred    = "INFERRED"
	RelationDerived     = "DERIVED"
	RelationUserDefined = "USER_DEFINED"
)

// Bounds on the projection. They cap what one tool result can put in front of
// a model; the full report stays on the RCA page (every item deep-links there).
const (
	MaxRCAChainSteps     = 12
	MaxRCAHypotheses     = 5
	MaxRCAEvidenceLines  = 8
	MaxRCAAffectedPerSet = 25
	MaxRCAImpactMeasures = 10
)

// RelationFor maps the engine's epistemic state onto a relation class. An
// unrecognised state is INFERRED — the conservative reading: nothing is
// promoted to "observed" by a vocabulary it does not recognise.
func RelationFor(epistemic string) string {
	switch strings.ToLower(strings.TrimSpace(epistemic)) {
	case "observed", "corroborated":
		return RelationObserved
	case "reported":
		return RelationUserDefined
	case "derived":
		return RelationDerived
	}
	return RelationInferred
}

// RCAResult is the engine's conclusion for ONE incident, projected for Iris.
type RCAResult struct {
	IncidentID string
	DisplayID  string
	Title      string
	// Verdict is the report's analysis state (observed | suspected | probable |
	// confirmed | inconclusive) and RootCauseState its root-cause state
	// (not_identified | under_investigation | confirmed); Confidence is the
	// ENGINE's number for the leading hypothesis, never a model's.
	Verdict         string
	RootCauseState  string
	Confidence      float64
	ConfidenceLabel string
	RootCause       RCARootCause
	Localization    RCALocalization
	CausalChain     []RCACausalLink
	// ChainNote is the engine's honest sentence when no chain is proposed.
	ChainNote string
	// PrimaryContradicted: the primary sequence's hypothesis has been
	// contradicted; the chain stays for the record.
	PrimaryContradicted bool
	Hypotheses          []RCAHypothesis
	Affected            RCAAffected
	Impact              []RCAImpact
	Owner               RCAOwner
	// Missing is the evidence the engine says it still needs.
	Missing   []string
	Truncated bool
}

// RCARootCause mirrors the engine's root-cause block, including its honesty
// rule: Identified is set only when a mechanism AND an object are established.
type RCARootCause struct {
	Identified    bool
	Statement     string
	Mechanism     string
	Object        string
	ObjectType    string
	PossibleCause string
	Known         []string
	Missing       []string
}

// RCALocalization is WHERE the evidence converges — never the cause.
type RCALocalization struct {
	Localized  bool
	Statement  string
	Object     string
	ObjectType string
}

// RCACausalLink is one step of the proposed propagation.
type RCACausalLink struct {
	Number         int
	Claim          string
	Role           string
	Relation       string // OBSERVED | INFERRED | DERIVED | USER_DEFINED
	EpistemicState string // the engine's own word
	Basis          string
	Interval       string
	Link           string // "followed by" etc. — temporal language only
	Evidence       []string
	Contradictions []string
}

// RCAHypothesis is one ranked candidate with the evidence for AND against it.
type RCAHypothesis struct {
	Rank          int
	Title         string
	Problem       string
	CausalRole    string
	Candidacy     string
	Confidence    float64
	Label         string
	Supporting    []string
	Contradicting []string
	Missing       []string
	ConfirmWhen   []string
	Owner         string
}

// RCAAffected is the deterministic blast radius from the engine's scope.
type RCAAffected struct {
	Services []string
	Devices  []string
	Sites    []string
	Targets  []string
	Seams    []string
	Regions  []string
	Paths    int
}

// RCAImpact is one impact measure with its provenance; Value is nil when the
// measure was not measured (never zero).
type RCAImpact struct {
	Measure, Label, Status, Unit, Scope, Source, Basis string
	Value                                              *float64
}

// RCAOwner is the engine's ownership decision.
type RCAOwner struct {
	Triage, TriageReason      string
	SuspectedDomain           string
	Technical                 string
	ExternalCandidate         string
	Demarcation               string
	Escalation, EscalationWhy string
	Candidates                []string
}

// ---- the tools --------------------------------------------------------------

// rcaResultTool is the shared shape of the four N-B2 tools: one RCAResult
// read, a different projection each.
type rcaResultTool struct {
	deps    TroubleshootDeps
	name    string
	project func(RCAResult, *ToolResult)
}

func (t rcaResultTool) Name() string            { return t.name }
func (t rcaResultTool) Module() string          { return "correlations_rca" }
func (t rcaResultTool) Capability() Capability  { return CapRead }
func (t rcaResultTool) RequiredPerms() []string { return []string{"correlations:read"} }
func (t rcaResultTool) Freshness() Freshness    { return FreshnessLive }

func (t rcaResultTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	id, err := validIDArg("correlation_id", args["correlation_id"], 64)
	if err != nil {
		return ToolResult{}, err
	}
	res, err := t.deps.RCAResult(ctx, p, id)
	if err != nil {
		return ToolResult{}, err // ErrNotFound for unknown OR another tenant's incident
	}
	tr := ToolResult{Truncated: res.Truncated}
	t.project(res, &tr)
	return tr, nil
}

func rcaHref(res RCAResult) string { return "#/monitoring/correlations?id=" + res.IncidentID }

func rcaItem(res RCAResult, cite, kind, text string) EvidenceItem {
	return EvidenceItem{CitationID: cite + ":" + res.IncidentID, Kind: kind, Text: clampText(text, maxToolTextChars), Href: rcaHref(res)}
}

// projectCausalChain — get_causal_chain.
func projectCausalChain(res RCAResult, tr *ToolResult) {
	if len(res.CausalChain) == 0 {
		note := firstNonEmpty(res.ChainNote, "no causal sequence is proposed for this incident")
		tr.Notes = append(tr.Notes, note+" — say so; do not invent one")
		return
	}
	for _, l := range res.CausalChain {
		text := fmt.Sprintf("step %d [%s, engine: %s] %s", l.Number, l.Relation, l.EpistemicState, l.Claim)
		if l.Link != "" {
			text += " (" + l.Link + ")"
		}
		if l.Interval != "" {
			text += "; " + l.Interval
		}
		if len(l.Contradictions) > 0 {
			text += "; CONTRADICTED BY: " + strings.Join(l.Contradictions, "; ")
		}
		tr.Items = append(tr.Items, rcaItem(res, fmt.Sprintf("chain-%d", l.Number), "finding", text))
	}
	if res.PrimaryContradicted {
		tr.Notes = append(tr.Notes, "the primary sequence's hypothesis is CONTRADICTED by evidence — present it as disputed")
	}
	tr.Notes = append(tr.Notes, "steps are the engine's PROPOSED propagation order: an INFERRED step must be worded as inferred, and where only timing links two steps say \"followed by\", never \"caused\"")
}

// projectBlastRadius — get_blast_radius.
func projectBlastRadius(res RCAResult, tr *ToolResult) {
	a := res.Affected
	add := func(label string, xs []string) {
		if len(xs) > 0 {
			tr.Items = append(tr.Items, rcaItem(res, "blast-"+label, "topology", "affected "+label+": "+strings.Join(xs, ", ")))
		}
	}
	add("services", a.Services)
	add("sites", a.Sites)
	add("devices", a.Devices)
	add("targets", a.Targets)
	add("seams", a.Seams)
	add("regions", a.Regions)
	if a.Paths > 0 {
		tr.Items = append(tr.Items, rcaItem(res, "blast-paths", "topology", fmt.Sprintf("affected paths: %d", a.Paths)))
	}
	for _, m := range res.Impact {
		text := m.Label + ": "
		if m.Value == nil {
			text += "not measured — " + m.Basis
		} else {
			text += strings.TrimSpace(fmt.Sprintf("%g %s", *m.Value, m.Unit)) + " (" + m.Status + "; source " + firstNonEmpty(m.Source, "engine") + ") — " + m.Basis
		}
		tr.Items = append(tr.Items, rcaItem(res, "impact-"+m.Measure, "finding", text))
	}
	if len(tr.Items) == 0 {
		tr.Notes = append(tr.Notes, "the engine recorded no affected entities for this incident — say the blast radius is unknown, not empty")
	}
	tr.Notes = append(tr.Notes, "impact numbers are the engine's, with provenance; a measure marked not measured is unknown, never zero — do not estimate user counts")
}

// projectOwner — get_owner.
func projectOwner(res RCAResult, tr *ToolResult) {
	o := res.Owner
	if o.Triage != "" {
		tr.Items = append(tr.Items, rcaItem(res, "owner-triage", "finding", "triage owner: "+o.Triage+" — "+o.TriageReason))
	}
	if o.Technical != "" {
		tr.Items = append(tr.Items, rcaItem(res, "owner-technical", "finding", "technical owner: "+o.Technical))
	}
	if o.SuspectedDomain != "" {
		tr.Items = append(tr.Items, rcaItem(res, "owner-domain", "finding", "suspected domain: "+o.SuspectedDomain))
	}
	if o.ExternalCandidate != "" {
		tr.Items = append(tr.Items, rcaItem(res, "owner-external", "finding",
			"external candidate: "+o.ExternalCandidate+" (demarcation: "+firstNonEmpty(o.Demarcation, "not_started")+")"))
	}
	if o.Escalation != "" {
		tr.Items = append(tr.Items, rcaItem(res, "owner-escalation", "finding", "escalate to: "+o.Escalation+" — "+o.EscalationWhy))
	}
	if len(o.Candidates) > 0 {
		tr.Items = append(tr.Items, rcaItem(res, "owner-candidates", "finding", "possible owners: "+strings.Join(o.Candidates, "; ")))
	}
	if len(tr.Items) == 0 {
		tr.Notes = append(tr.Notes, "the engine named no owner for this incident — say so; never guess an owner")
		return
	}
	tr.Notes = append(tr.Notes, "ownership is the engine's deterministic decision: an external provider is never named accountable before demarcation is confirmed")
}

// projectConfidence — get_confidence_breakdown: the ranked candidates with the
// evidence FOR and AGAINST each (Part 1 §12: contradictions are never hidden).
func projectConfidence(res RCAResult, tr *ToolResult) {
	tr.Items = append(tr.Items, rcaItem(res, "confidence", "finding",
		fmt.Sprintf("engine analysis %s, root cause %s; leading candidate %s (%.0f%% engine confidence)",
			firstNonEmpty(res.Verdict, "inconclusive"), firstNonEmpty(res.RootCauseState, "not_identified"),
			firstNonEmpty(res.ConfidenceLabel, "unlabelled"), res.Confidence*100)))
	for _, h := range res.Hypotheses {
		text := fmt.Sprintf("#%d %s — %s; %s (%.0f%%)", h.Rank, firstNonEmpty(h.Title, h.Problem), firstNonEmpty(h.CausalRole, "candidate"),
			firstNonEmpty(h.Label, "unlabelled"), h.Confidence*100)
		if len(h.Supporting) > 0 {
			text += "; FOR: " + strings.Join(h.Supporting, "; ")
		}
		if len(h.Contradicting) > 0 {
			text += "; AGAINST: " + strings.Join(h.Contradicting, "; ")
		}
		if len(h.Missing) > 0 {
			text += "; MISSING: " + strings.Join(h.Missing, "; ")
		}
		tr.Items = append(tr.Items, rcaItem(res, fmt.Sprintf("hypothesis-%d", h.Rank), "finding", text))
	}
	if len(res.Missing) > 0 {
		tr.Items = append(tr.Items, rcaItem(res, "missing", "finding", "evidence the engine still needs: "+strings.Join(res.Missing, "; ")))
	}
	tr.Notes = append(tr.Notes, "the confidence is the ENGINE's, not yours — report it, never raise it; always state the evidence AGAINST the leading candidate when there is any")
}

// AddRCATools registers the N-B2 tools when the RCAResult seam is wired.
func (r *ToolRegistry) AddRCATools(d TroubleshootDeps) {
	if d.RCAResult == nil {
		return
	}
	for _, t := range []rcaResultTool{
		{deps: d, name: "get_causal_chain", project: projectCausalChain},
		{deps: d, name: "get_blast_radius", project: projectBlastRadius},
		{deps: d, name: "get_owner", project: projectOwner},
		{deps: d, name: "get_confidence_breakdown", project: projectConfidence},
	} {
		r.add(t)
	}
}
