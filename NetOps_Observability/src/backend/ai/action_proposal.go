// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// action_proposal.go — where Iris PROPOSES a write (tracker 337 N-I4, gate 1).
//
// The only place a proposal can start is the read-only Investigator's own
// concluding step: an investigation that CONCLUDED (at least one supported
// line of investigation) on a server-resolved CASE. The engine hands the
// server an ActionSeed built from that investigation's own evidence; the
// server builds each payload (internal/irisaction) and returns what it
// proposed. Nothing here sends anything: execution happens only after a
// different person approves on /api/ai/actions.
//
// Why this is not a tool. Registering a write tool in the agent's registry
// would weaken a structural invariant (toolcontract.go: a CapWrite tool is not
// registrable, so the agent toolbox is read-only by construction). A model
// therefore cannot name a write; the proposal is an authored step of the
// investigation, decided by the server from server facts.

import (
	"context"
	"strings"
)

// ActionSeed is what a concluded investigation offers the proposal step. Every
// field is server-built from the investigation; the model's narrative appears
// only as the grounded answer text, and only as quoted evidence for a human.
type ActionSeed struct {
	Target     InvestigationTarget
	Engine     *InvestigationEngine
	Title      string
	Text       string
	Citations  []Citation
	Skills     []string
	DecisionID string
}

// ActionProposal is one write Iris proposed (or declined to), as shown on the
// answer card. It never carries the payload text — the approver reads that on
// the approval page.
type ActionProposal struct {
	ID       string `json:"id,omitempty"`
	Kind     string `json:"kind"`
	Label    string `json:"label"`
	Summary  string `json:"summary"`
	Status   string `json:"status"` // proposed | dry_run | existing
	Policy   string `json:"policy"`
	Note     string `json:"note,omitempty"`
	Approval string `json:"approval_href,omitempty"`
}

// ProposeActionsFunc is the server's proposal step.
type ProposeActionsFunc func(ctx context.Context, p Principal, seed ActionSeed) []ActionProposal

// maxActionProposals bounds the cards one answer carries.
const maxActionProposals = 2

// proposeFromInvestigation runs the server's proposal step for a concluded
// investigation. It is a no-op when no step is wired, when the investigation
// did not conclude, or when no case was resolved — the evidence-participation
// rule: no case, no proposal.
func (o *Orchestrator) proposeFromInvestigation(ctx context.Context, p Principal, tr *InvestigationTrace, ans *Answer) {
	if o.ProposeActions == nil || tr == nil || ans == nil || tr.Status != InvestigationStatusConcluded {
		return
	}
	if strings.TrimSpace(tr.Target.CorrelationID) == "" {
		return
	}
	seed := ActionSeed{
		Target: tr.Target, Engine: tr.Engine, Title: ans.Title, Text: ans.Text,
		Citations: append([]Citation(nil), ans.Citations...), DecisionID: ans.DecisionID,
	}
	seen := map[string]bool{}
	for _, pass := range tr.Passes {
		for _, hop := range pass.Chain {
			if hop.Name != "" && !seen[hop.Name] {
				seen[hop.Name] = true
				seed.Skills = append(seed.Skills, hop.Name)
			}
		}
	}
	out := o.ProposeActions(ctx, p, seed)
	if len(out) > maxActionProposals {
		out = out[:maxActionProposals]
	}
	ans.ActionProposals = out
}
