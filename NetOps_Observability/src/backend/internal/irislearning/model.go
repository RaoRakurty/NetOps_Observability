// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package irislearning is Iris's controlled learning loop (tracker 337 N-F5,
// plan §5 Phase F): what operators already told Correlix — how incidents were
// fixed, which entity an answer should have meant, which questions Iris could
// not answer — is turned into PROPOSED updates to the workspace's own
// knowledge, and a person decides each one.
//
// WHAT IT NEVER DOES. Nothing retrains a model and nothing activates on its
// own. A proposal is a draft with its sources cited; it reaches Iris only
// through the store it targets, under that store's own rules:
//
//   - a Network context fact (internal/orgcontext, N-F1): adopting it writes a
//     draft version AUTHORED BY THE ADOPTER and sends it for review; a
//     DIFFERENT person approves it (orgcontext.Apply refuses a self-approval,
//     and the database refuses it again);
//   - a tenant runbook (internal/tenantrunbook, N-F2): adopting it creates a
//     DRAFT procedure the team finishes on the Runbooks page, where its cases
//     run and a second person approves — this package never submits or
//     approves a runbook;
//   - an Iris alias (internal/entityalias, N-C2), which has no review of its
//     own: here the adopter and the approver must differ, and the approver's
//     step re-runs the alias checks (catalog shape, the entity is visible, the
//     text does not already mean something else) before the alias is written.
//
// PRIVACY. A generator reads only the caller's own tenant. A proposal's DRAFT
// — the text that would reach a prompt once approved — is built from closed
// vocabularies and server-derived names only. An operator's free-text
// resolution note is shown to the reviewer as quoted evidence and never enters
// a draft, so it never reaches a model. Colleagues' question wording is never
// copied: an alias phrase is proposed only when at least two different people
// used it.
//
// §3a. The tenant comes from the authenticated principal; the Postgres store
// runs inside WithTenant under the FORCE-RLS tenant_iso policy. Another
// tenant's proposal and one that does not exist are the same ErrNotFound.
//
// Stdlib + pgx (CLAUDE.md §6 allowlist).
package irislearning

import (
	"errors"
	"strings"
	"time"

	"netops/backend/internal/orgcontext"
)

// Bounds.
const (
	MaxProposalsPerTenant = 200
	MaxOpenPerTenant      = 50 // proposals still waiting for a person
	MaxEvidence           = 20 // per proposal; EvidenceCount keeps the true total
	MaxQuoteRunes         = 500
	MaxReasonBytes        = orgcontext.MaxReasonBytes
)

// Target is the store a proposal would change.
type Target string

const (
	TargetContext Target = "org_context"
	TargetRunbook Target = "runbook"
	TargetAlias   Target = "alias"
)

// ValidTarget reports whether t is known.
func ValidTarget(t Target) bool {
	return t == TargetContext || t == TargetRunbook || t == TargetAlias
}

// Generator names where a proposal came from.
type Generator string

const (
	// GenResolutionPattern: several incidents on one device were fixed the
	// same way (internal/rcaresolution + internal/incidentfp).
	GenResolutionPattern Generator = "resolution_pattern"
	// GenEntityCorrection: operators corrected answers to mean one entity,
	// using the same words (internal/irisquerylog corrections).
	GenEntityCorrection Generator = "entity_correction"
	// GenMissCluster: Iris could not answer a cluster of questions for want
	// of a tool or of data (internal/iristriage classes).
	GenMissCluster Generator = "miss_cluster"
)

// State is a proposal's lifecycle state.
//
//	proposed ─adopt──▶ adopted ─approve──▶ applied
//	proposed ─dismiss─▶ dismissed
//
// "adopted" means handed to the target's review: a pending Network context
// version, a runbook draft, or an alias waiting for a second person. Whether
// the target then went live is read from the target itself (TargetState).
type State string

const (
	StateProposed  State = "proposed"
	StateAdopted   State = "adopted"
	StateApplied   State = "applied"
	StateDismissed State = "dismissed"
)

// ContextDraft is a proposed Network context fact.
type ContextDraft struct {
	Scope string          `json:"scope"`
	Kind  orgcontext.Kind `json:"kind"`
	Key   string          `json:"key"`
	Body  string          `json:"body"`
}

// RunbookDraft is a proposed procedure (always a MOP: a draft for people to
// finish, never something Iris runs).
type RunbookDraft struct {
	Name    string `json:"name"`
	SkillMD string `json:"skill_md"`
}

// AliasDraft is a proposed Iris alias.
type AliasDraft struct {
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	Alias      string `json:"alias"`
}

// Evidence is one source a proposal cites.
type Evidence struct {
	Kind  string    `json:"kind"` // resolution | correction | miss
	Ref   string    `json:"ref"`  // the case id, query-log record id, …
	At    time.Time `json:"at"`
	Label string    `json:"label"` // server-written, from closed vocabularies
	// Quote is operator-written text shown to the REVIEWER only (an RCA
	// resolution note). It never enters a draft and never reaches a model.
	Quote string `json:"quote,omitempty"`
}

// Proposal is one suggested update.
type Proposal struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"-"`
	Target    Target    `json:"target"`
	Generator Generator `json:"generator"`
	// Subject is the within-tenant identity of what is proposed: the same
	// generator never holds two proposals about one subject.
	Subject string `json:"subject"`
	Title   string `json:"title"`
	Why     string `json:"why"`

	Context *ContextDraft `json:"context,omitempty"`
	Runbook *RunbookDraft `json:"runbook,omitempty"`
	Alias   *AliasDraft   `json:"alias,omitempty"`

	Evidence      []Evidence `json:"evidence"`
	EvidenceCount int        `json:"evidence_count"`

	State     State      `json:"state"`
	AdoptedBy string     `json:"adopted_by,omitempty"`
	AdoptedAt *time.Time `json:"adopted_at,omitempty"`
	DecidedBy string     `json:"decided_by,omitempty"` // who approved (alias) or dismissed
	DecidedAt *time.Time `json:"decided_at,omitempty"`
	Reason    string     `json:"reason,omitempty"` // a dismissal's reason

	TargetID      string `json:"target_id,omitempty"`      // the fact / runbook id, or the alias key
	TargetVersion int    `json:"target_version,omitempty"` // the version sent for review

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// draftOK reports whether the proposal carries exactly the draft its target
// needs.
func (p Proposal) draftOK() bool {
	switch p.Target {
	case TargetContext:
		return p.Context != nil && p.Runbook == nil && p.Alias == nil
	case TargetRunbook:
		return p.Runbook != nil && p.Context == nil && p.Alias == nil
	case TargetAlias:
		return p.Alias != nil && p.Context == nil && p.Runbook == nil
	}
	return false
}

// Placeholder opens a part of a draft a person must fill in before adopting.
const Placeholder = "{{"

// HasPlaceholder reports whether s still carries an unfilled part.
func HasPlaceholder(s string) bool { return strings.Contains(s, Placeholder) }

// Errors. ErrNotFound covers another tenant's proposal.
var (
	ErrNotFound     = errors.New("irislearning: not found")
	ErrInvalid      = errors.New("irislearning: invalid")
	ErrWrongState   = errors.New("irislearning: not possible in the current state")
	ErrSelfApproval = errors.New("irislearning: the person who adopted a proposal cannot approve it")
	ErrUnfinished   = errors.New("irislearning: the draft still has parts to fill in")
	ErrFull         = errors.New("irislearning: limit reached")
	ErrConflict     = errors.New("irislearning: the alias already means something else")
	ErrReviewElse   = errors.New("irislearning: this proposal is approved where it lives")
)

// ValidID reports whether id is a lower-case UUID.
func ValidID(id string) bool { return orgcontext.ValidID(id) }

// NewID returns a random (v4) UUID.
func NewID() (string, error) { return orgcontext.NewID() }
