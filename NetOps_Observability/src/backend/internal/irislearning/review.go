// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irislearning

// review.go — what a person can do to a proposal, and how each target's OWN
// rules carry it the rest of the way. Nothing here activates anything: a
// Network context version goes live only through orgcontext's approval (a
// different person, bound to the reviewed text), a runbook only through its own
// page (cases + a different person), an alias only after a second person here.

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/entityalias"
	"netops/backend/internal/orgcontext"
	"netops/backend/internal/tenantrunbook"
)

// AliasStore is the alias table seam (entityalias.Store satisfies it).
type AliasStore interface {
	Validate(a *entityalias.Alias) error
	Put(a entityalias.Alias) (entityalias.Alias, error)
	List(tenant string, cross bool) []entityalias.Alias
}

// Targets are the stores a proposal can change. A nil store refuses its
// target (ErrInvalid) instead of pretending.
type Targets struct {
	Context   orgcontext.Store
	Runbooks  tenantrunbook.Store
	Aliases   AliasStore
	ToolNames func() []string
	// ContextChanged is called after a fact went live (cache invalidation).
	ContextChanged func(tenant string)
}

// Visible reports whether the person acting can see an entity (an alias may
// only point at something they can see).
type Visible func(ctx context.Context, entityType, entityID string) (bool, error)

// Edit is what a person may change before adopting: the parts of the draft
// that are theirs to word. Empty fields keep the draft's value.
type Edit struct {
	Key     string `json:"key,omitempty"`
	Body    string `json:"body,omitempty"`
	Alias   string `json:"alias,omitempty"`
	Name    string `json:"name,omitempty"`
	SkillMD string `json:"skill_md,omitempty"`
}

func (t Targets) tools() []string {
	if t.ToolNames == nil {
		return nil
	}
	return t.ToolNames()
}

// applyEdit returns the proposal's draft with the person's edits.
func applyEdit(p Proposal, e Edit) Proposal {
	p = clone(p)
	switch p.Target {
	case TargetContext:
		if e.Key != "" {
			p.Context.Key = e.Key
		}
		if e.Body != "" {
			p.Context.Body = e.Body
		}
	case TargetAlias:
		if e.Alias != "" {
			p.Alias.Alias = strings.TrimSpace(e.Alias)
		}
	case TargetRunbook:
		if e.Name != "" {
			p.Runbook.Name = e.Name
		}
		if e.SkillMD != "" {
			p.Runbook.SkillMD = e.SkillMD
		}
	}
	return p
}

// checkAlias runs every alias rule: the catalog shape, the entity is visible
// to the person, the text does not already mean something else. It returns
// the normalized alias.
func (t Targets) checkAlias(ctx context.Context, tenant string, d AliasDraft, visible Visible) (entityalias.Alias, error) {
	if t.Aliases == nil {
		return entityalias.Alias{}, ErrInvalid
	}
	a := entityalias.Alias{TenantID: tenant, EntityType: d.EntityType, EntityID: d.EntityID, Alias: d.Alias,
		Source: entityalias.SourceSuggestion}
	if err := t.Aliases.Validate(&a); err != nil {
		return entityalias.Alias{}, err
	}
	// Provider and application ids are names the alias itself defines; every
	// other entity must be one the person can see (the alias API's rule).
	if a.EntityType != "provider" && a.EntityType != "application" {
		if visible == nil {
			return entityalias.Alias{}, ErrNotFound
		}
		ok, err := visible(ctx, a.EntityType, a.EntityID)
		if err != nil {
			return entityalias.Alias{}, err
		}
		if !ok {
			return entityalias.Alias{}, ErrNotFound
		}
	}
	for _, cur := range t.Aliases.List(tenant, false) {
		if cur.Key() == a.Key() && cur.EntityID != a.EntityID {
			return entityalias.Alias{}, ErrConflict
		}
	}
	return a, nil
}

// Adopt hands a proposal to its target's review, as actor: a Network context
// version authored by actor and sent for review, a runbook draft owned by
// actor, or an alias waiting for a second person.
func Adopt(ctx context.Context, s Store, t Targets, tenant, actor, id string, e Edit, visible Visible, now time.Time) (Proposal, error) {
	p, err := s.Get(ctx, tenant, id)
	if err != nil {
		return Proposal{}, err
	}
	if p.State != StateProposed {
		return Proposal{}, ErrWrongState
	}
	p = applyEdit(p, e)
	var targetID string
	var version int
	switch p.Target {
	case TargetContext:
		targetID, version, err = t.adoptContext(ctx, tenant, actor, *p.Context)
	case TargetRunbook:
		targetID, version, err = t.adoptRunbook(ctx, tenant, actor, *p.Runbook)
	case TargetAlias:
		if HasPlaceholder(p.Alias.Alias) {
			return Proposal{}, ErrUnfinished
		}
		var a entityalias.Alias
		a, err = t.checkAlias(ctx, tenant, *p.Alias, visible)
		if err == nil {
			p.Alias.Alias = a.Alias
			targetID = a.Key()
		}
	default:
		err = ErrInvalid
	}
	if err != nil {
		return Proposal{}, err
	}
	return s.Update(ctx, tenant, id, func(cur *Proposal) error {
		if cur.State != StateProposed {
			return ErrWrongState // someone else acted first
		}
		cur.Context, cur.Runbook, cur.Alias = p.Context, p.Runbook, p.Alias
		cur.State, cur.AdoptedBy, cur.AdoptedAt = StateAdopted, actor, &now
		cur.TargetID, cur.TargetVersion, cur.UpdatedAt = targetID, version, now
		return nil
	})
}

func (t Targets) adoptContext(ctx context.Context, tenant, actor string, d ContextDraft) (string, int, error) {
	if t.Context == nil {
		return "", 0, ErrInvalid
	}
	if HasPlaceholder(d.Key) || HasPlaceholder(d.Body) {
		return "", 0, ErrUnfinished
	}
	if err := orgcontext.CheckKey(d.Key); err != nil {
		return "", 0, err
	}
	if err := orgcontext.CheckBody(d.Kind, d.Body, t.tools()); err != nil {
		return "", 0, err
	}
	docs, err := t.Context.List(ctx, tenant)
	if err != nil {
		return "", 0, err
	}
	var doc orgcontext.Doc
	found := false
	for _, x := range docs {
		if x.Scope == d.Scope && x.Kind == d.Kind && x.Key == d.Key {
			doc, found = x, true
			break
		}
	}
	if found {
		doc, err = t.Context.Do(ctx, tenant, doc.ID, orgcontext.Op{Kind: orgcontext.OpDraft, Actor: actor, Body: d.Body})
		if errors.Is(err, orgcontext.ErrNotAuthor) {
			err = ErrWrongState // a colleague already has a draft open on this fact
		}
	} else {
		doc, err = t.Context.Create(ctx, tenant, actor, orgcontext.NewDoc{Scope: d.Scope, Kind: d.Kind, Key: d.Key, Body: d.Body})
	}
	if err != nil {
		return "", 0, err
	}
	doc, err = t.Context.Do(ctx, tenant, doc.ID, orgcontext.Op{Kind: orgcontext.OpSubmit, Actor: actor})
	if err != nil {
		return "", 0, err
	}
	v, ok := doc.Open()
	if !ok || v.State != orgcontext.StatePending {
		return "", 0, ErrWrongState
	}
	return doc.ID, v.Version, nil
}

func (t Targets) adoptRunbook(ctx context.Context, tenant, actor string, d RunbookDraft) (string, int, error) {
	if t.Runbooks == nil {
		return "", 0, ErrInvalid
	}
	rb, err := t.Runbooks.Create(ctx, tenant, actor, tenantrunbook.NewRunbook{Name: d.Name, Kind: tenantrunbook.KindMOP,
		Source: tenantrunbook.Source{SkillMD: d.SkillMD}})
	if err != nil {
		return "", 0, err
	}
	return rb.ID, 1, nil
}

// Approve is the second person's step. For a Network context fact it is
// orgcontext's own approval of exactly the version that was sent for review
// (orgcontext refuses the author); for an alias it re-runs every alias check
// and writes it, refusing the person who adopted it. A runbook is approved on
// its own page, where its cases run (ErrReviewElse).
func Approve(ctx context.Context, s Store, t Targets, tenant, actor, id string, visible Visible, now time.Time) (Proposal, error) {
	p, err := s.Get(ctx, tenant, id)
	if err != nil {
		return Proposal{}, err
	}
	if p.State != StateAdopted {
		return Proposal{}, ErrWrongState
	}
	switch p.Target {
	case TargetRunbook:
		return Proposal{}, ErrReviewElse
	case TargetContext:
		if err := t.approveContext(ctx, tenant, actor, p); err != nil {
			return Proposal{}, err
		}
	case TargetAlias:
		if actor == p.AdoptedBy {
			return Proposal{}, ErrSelfApproval
		}
		a, err := t.checkAlias(ctx, tenant, *p.Alias, visible)
		if err != nil {
			return Proposal{}, err
		}
		a.CreatedBy = p.AdoptedBy
		if _, err := t.Aliases.Put(a); err != nil {
			return Proposal{}, err
		}
	default:
		return Proposal{}, ErrInvalid
	}
	return s.Update(ctx, tenant, id, func(cur *Proposal) error {
		if cur.State != StateAdopted {
			return ErrWrongState
		}
		cur.State, cur.DecidedBy, cur.DecidedAt, cur.UpdatedAt = StateApplied, actor, &now, now
		return nil
	})
}

func (t Targets) approveContext(ctx context.Context, tenant, actor string, p Proposal) error {
	if t.Context == nil {
		return ErrInvalid
	}
	doc, err := t.Context.Get(ctx, tenant, p.TargetID)
	if err != nil {
		return err
	}
	var v orgcontext.Version
	found := false
	for _, x := range doc.Versions {
		if x.Version == p.TargetVersion {
			v, found = x, true
		}
	}
	if !found || v.State != orgcontext.StatePending {
		return ErrWrongState
	}
	if _, err := t.Context.Do(ctx, tenant, doc.ID, orgcontext.Op{Kind: orgcontext.OpApprove, Actor: actor,
		Version: v.Version, BodySHA256: v.BodySHA256, Reason: "approved from an Iris learning proposal"}); err != nil {
		return err
	}
	if t.ContextChanged != nil {
		t.ContextChanged(tenant)
	}
	return nil
}

// Dismiss declines a proposal that nobody adopted, with a reason. A dismissed
// subject is never proposed again.
func Dismiss(ctx context.Context, s Store, tenant, actor, id, reason string, now time.Time) (Proposal, error) {
	if err := orgcontext.CheckReason(reason, true); err != nil {
		return Proposal{}, err
	}
	return s.Update(ctx, tenant, id, func(cur *Proposal) error {
		if cur.State != StateProposed {
			return ErrWrongState
		}
		cur.State, cur.DecidedBy, cur.DecidedAt, cur.Reason, cur.UpdatedAt = StateDismissed, actor, &now, reason, now
		return nil
	})
}

// TargetState reads what became of an adopted proposal where it lives:
// pending / active / rejected / … for a fact or runbook version, "waiting"
// or "written" for an alias. "" when there is nothing to read.
func (t Targets) TargetState(ctx context.Context, tenant string, p Proposal) string {
	switch {
	case p.State == StateProposed || p.State == StateDismissed:
		return ""
	case p.Target == TargetAlias:
		if p.State == StateApplied {
			return "written"
		}
		return "waiting_for_second_person"
	case p.Target == TargetContext && t.Context != nil:
		doc, err := t.Context.Get(ctx, tenant, p.TargetID)
		if err != nil {
			return "gone"
		}
		return versionState(doc.Versions, p.TargetVersion)
	case p.Target == TargetRunbook && t.Runbooks != nil:
		rb, err := t.Runbooks.Get(ctx, tenant, p.TargetID)
		if err != nil {
			return "gone"
		}
		if v, ok := rb.Active(); ok {
			return "active (version " + strconv.Itoa(v.Version) + ")"
		}
		if v, ok := rb.Open(); ok {
			return string(v.State)
		}
		return versionState(rb.Versions, p.TargetVersion)
	}
	return ""
}

func versionState(vs []orgcontext.Version, n int) string {
	for _, v := range vs {
		if v.Version == n {
			return string(v.State)
		}
	}
	return "gone"
}
