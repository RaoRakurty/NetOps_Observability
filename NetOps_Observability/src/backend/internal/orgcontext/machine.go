// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package orgcontext

// machine.go — THE state machine, as pure functions over one document. Both
// stores load the document, apply one of these, and persist the difference,
// so the memory store (tests, previews) and the Postgres store cannot drift.
//
//	(none)  ─create──▶ draft ─submit──▶ pending ─approve──▶ active ─retire──▶ retired
//	           draft ◀─withdraw─ pending ─reject──▶ rejected   active ─(newer active)─▶ superseded
//	any earlier APPROVED version ─rollback──▶ a NEW active version (author + approver kept)

import (
	"strings"
	"time"
)

// Op is one requested transition.
type Op struct {
	Kind       OpKind
	Actor      string // the authenticated person (claims.Sub)
	Body       string // draft
	Version    int    // approve / reject: the version reviewed
	BodySHA256 string // approve: the text reviewed
	ToVersion  int    // rollback
	Reason     string // reject (required) / rollback / retire (required)
	Now        time.Time
}

// OpKind names a transition.
type OpKind string

const (
	OpDraft    OpKind = "draft"    // create or edit the open draft
	OpDiscard  OpKind = "discard"  // delete the open draft
	OpSubmit   OpKind = "submit"   // draft → pending
	OpWithdraw OpKind = "withdraw" // pending → draft
	OpApprove  OpKind = "approve"  // pending → active (another person)
	OpReject   OpKind = "reject"   // pending → rejected (another person)
	OpRollback OpKind = "rollback" // earlier approved version → new active version
	OpRetire   OpKind = "retire"   // active → retired
)

// Apply performs op on d (a copy is returned; d is not modified). The result
// is what the store persists. It never touches a version's body or author
// once the version has left draft.
func Apply(d Doc, op Op) (Doc, error) {
	if strings.TrimSpace(op.Actor) == "" {
		return Doc{}, ErrInvalid
	}
	out := d
	out.Versions = append([]Version(nil), d.Versions...)
	now := op.Now.UTC()
	at := func(st State) int {
		for i, v := range out.Versions {
			if v.State == st {
				return i
			}
		}
		return -1
	}
	switch op.Kind {
	case OpDraft:
		if i := at(StateDraft); i >= 0 {
			if out.Versions[i].Author != op.Actor {
				return Doc{}, ErrNotAuthor
			}
			out.Versions[i].Body, out.Versions[i].BodySHA256 = op.Body, BodySHA256(op.Body)
			out.Versions[i].CreatedAt = now
		} else {
			if at(StatePending) >= 0 {
				return Doc{}, ErrWrongState // one open version at a time
			}
			if len(out.Versions) >= MaxVersionsPerDoc {
				return Doc{}, ErrFull
			}
			out.Versions = append(out.Versions, Version{Version: d.latest() + 1, Body: op.Body, BodySHA256: BodySHA256(op.Body),
				State: StateDraft, Author: op.Actor, CreatedAt: now})
		}
	case OpDiscard:
		i := at(StateDraft)
		if i < 0 {
			return Doc{}, ErrWrongState
		}
		if out.Versions[i].Author != op.Actor {
			return Doc{}, ErrNotAuthor
		}
		out.Versions = append(out.Versions[:i], out.Versions[i+1:]...)
	case OpSubmit, OpWithdraw:
		from, to := StateDraft, StatePending
		if op.Kind == OpWithdraw {
			from, to = StatePending, StateDraft
		}
		i := at(from)
		if i < 0 {
			return Doc{}, ErrWrongState
		}
		if out.Versions[i].Author != op.Actor {
			return Doc{}, ErrNotAuthor
		}
		out.Versions[i].State = to
	case OpApprove, OpReject:
		i := at(StatePending)
		if i < 0 || out.Versions[i].Version != op.Version {
			return Doc{}, ErrWrongState
		}
		if out.Versions[i].Author == op.Actor {
			return Doc{}, ErrSelfApproval
		}
		if op.Kind == OpReject {
			if strings.TrimSpace(op.Reason) == "" {
				return Doc{}, ErrInvalid
			}
			out.Versions[i].State, out.Versions[i].Reason, out.Versions[i].DecidedAt = StateRejected, op.Reason, &now
			out.Versions[i].DecidedBy = op.Actor
			break
		}
		if op.BodySHA256 != out.Versions[i].BodySHA256 {
			return Doc{}, ErrStale
		}
		if j := at(StateActive); j >= 0 {
			out.Versions[j].State = StateSuperseded
		}
		out.Versions[i].State, out.Versions[i].Approver, out.Versions[i].ActivatedBy = StateActive, op.Actor, op.Actor
		out.Versions[i].Reason, out.Versions[i].DecidedAt = op.Reason, &now
	case OpRollback:
		var target *Version
		for i := range out.Versions {
			if out.Versions[i].Version == op.ToVersion {
				target = &out.Versions[i]
			}
		}
		if target == nil {
			return Doc{}, ErrNotFound
		}
		// Only text that two people already approved can come back.
		if target.Approver == "" || target.State == StateActive {
			return Doc{}, ErrWrongState
		}
		if len(out.Versions) >= MaxVersionsPerDoc {
			return Doc{}, ErrFull
		}
		restored := Version{Version: d.latest() + 1, Body: target.Body, BodySHA256: target.BodySHA256, State: StateActive,
			Author: target.Author, Approver: target.Approver, ActivatedBy: op.Actor, RestoredFrom: target.Version,
			Reason: op.Reason, CreatedAt: now, DecidedAt: &now}
		if j := at(StateActive); j >= 0 {
			out.Versions[j].State = StateSuperseded
		}
		out.Versions = append(out.Versions, restored)
	case OpRetire:
		i := at(StateActive)
		if i < 0 {
			return Doc{}, ErrWrongState
		}
		if strings.TrimSpace(op.Reason) == "" {
			return Doc{}, ErrInvalid
		}
		out.Versions[i].State, out.Versions[i].Reason, out.Versions[i].DecidedAt = StateRetired, op.Reason, &now
		out.Versions[i].DecidedBy = op.Actor
	default:
		return Doc{}, ErrInvalid
	}
	out.UpdatedAt = now
	return out, nil
}
