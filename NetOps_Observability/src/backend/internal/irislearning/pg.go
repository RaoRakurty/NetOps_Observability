// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irislearning

// pg.go — the Postgres store over iris_learning_proposals (migration 0073).
// Every statement runs inside WithTenant(tenant, cross=false) under the
// FORCE-RLS tenant_iso policy; tenant_id is also filtered explicitly. Offer
// counts under a transaction-scoped advisory lock on the tenant so two
// concurrent refreshes cannot both pass the caps; Update loads the row
// FOR UPDATE. The table's CHECKs refuse what the code would not do (an alias
// applied by the person who adopted it, a dismissal without a reason).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DB is the injected relational seam.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// PGStore is the Postgres Store.
type PGStore struct{ db DB }

// NewPGStore builds the Postgres store.
func NewPGStore(db DB) *PGStore { return &PGStore{db: db} }

const pgTimeout = 10 * time.Second

const pgCols = `id, target, generator, subject, title, why, draft, evidence, evidence_count, state,
    adopted_by, adopted_at, decided_by, decided_at, reason, target_id, target_version, created_at, updated_at`

// draftDoc is the JSON shape of the draft column: exactly one member set.
type draftDoc struct {
	Context *ContextDraft `json:"context,omitempty"`
	Runbook *RunbookDraft `json:"runbook,omitempty"`
	Alias   *AliasDraft   `json:"alias,omitempty"`
}

func scanProposal(row pgx.Row, tenant string) (Proposal, error) {
	var (
		p                     Proposal
		target, gen, state    string
		draftRaw, evidenceRaw []byte
		adoptedAt, decidedAt  *time.Time
	)
	if err := row.Scan(&p.ID, &target, &gen, &p.Subject, &p.Title, &p.Why, &draftRaw, &evidenceRaw, &p.EvidenceCount, &state,
		&p.AdoptedBy, &adoptedAt, &p.DecidedBy, &decidedAt, &p.Reason, &p.TargetID, &p.TargetVersion, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return Proposal{}, err
	}
	p.TenantID, p.Target, p.Generator, p.State = tenant, Target(target), Generator(gen), State(state)
	var d draftDoc
	if err := json.Unmarshal(draftRaw, &d); err != nil {
		return Proposal{}, fmt.Errorf("draft: %w", err)
	}
	p.Context, p.Runbook, p.Alias = d.Context, d.Runbook, d.Alias
	if err := json.Unmarshal(evidenceRaw, &p.Evidence); err != nil {
		return Proposal{}, fmt.Errorf("evidence: %w", err)
	}
	if p.Evidence == nil {
		p.Evidence = []Evidence{}
	}
	if adoptedAt != nil {
		t := adoptedAt.UTC()
		p.AdoptedAt = &t
	}
	if decidedAt != nil {
		t := decidedAt.UTC()
		p.DecidedAt = &t
	}
	p.CreatedAt, p.UpdatedAt = p.CreatedAt.UTC(), p.UpdatedAt.UTC()
	return p, nil
}

func encode(p Proposal) (draft, evidence []byte, err error) {
	if draft, err = json.Marshal(draftDoc{Context: p.Context, Runbook: p.Runbook, Alias: p.Alias}); err != nil {
		return nil, nil, err
	}
	ev := p.Evidence
	if ev == nil {
		ev = []Evidence{}
	}
	if evidence, err = json.Marshal(ev); err != nil {
		return nil, nil, err
	}
	return draft, evidence, nil
}

// List implements Store.
func (s *PGStore) List(ctx context.Context, tenant string) ([]Proposal, error) {
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	out := []Proposal{}
	err := s.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pgCols+` FROM iris_learning_proposals
		    WHERE tenant_id = $1 ORDER BY updated_at DESC, id ASC LIMIT $2`, tenant, MaxProposalsPerTenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanProposal(rows, tenant)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("irislearning: list: %w", err)
	}
	return out, nil
}

// Get implements Store.
func (s *PGStore) Get(ctx context.Context, tenant, id string) (Proposal, error) {
	if !ValidID(id) {
		return Proposal{}, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out Proposal
	err := s.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		p, err := scanProposal(tx.QueryRow(ctx, `SELECT `+pgCols+` FROM iris_learning_proposals
		    WHERE tenant_id = $1 AND id = $2`, tenant, id), tenant)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		out = p
		return err
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Proposal{}, ErrNotFound
		}
		return Proposal{}, fmt.Errorf("irislearning: get: %w", err)
	}
	return out, nil
}

// Offer implements Store.
func (s *PGStore) Offer(ctx context.Context, tenant string, ps []Proposal, now time.Time) (int, int, error) {
	if tenant == "" {
		return 0, 0, ErrInvalid
	}
	for _, f := range ps {
		if err := checkOffered(f); err != nil {
			return 0, 0, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	added, refreshed := 0, 0
	err := s.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('iris_learning:' || $1::text))`, tenant); err != nil {
			return fmt.Errorf("lock: %w", err)
		}
		var total, open int
		if err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE state = 'proposed')
		    FROM iris_learning_proposals WHERE tenant_id = $1`, tenant).Scan(&total, &open); err != nil {
			return fmt.Errorf("count: %w", err)
		}
		for _, f := range ps {
			cur, err := scanProposal(tx.QueryRow(ctx, `SELECT `+pgCols+` FROM iris_learning_proposals
			    WHERE tenant_id = $1 AND generator = $2 AND subject = $3 FOR UPDATE`, tenant, string(f.Generator), f.Subject), tenant)
			switch {
			case err == nil:
				next, changed := Merge(cur, f, now)
				if !changed {
					continue
				}
				if err := update(ctx, tx, tenant, next); err != nil {
					return err
				}
				refreshed++
				continue
			case !errors.Is(err, pgx.ErrNoRows):
				return fmt.Errorf("read: %w", err)
			}
			if total >= MaxProposalsPerTenant || open >= MaxOpenPerTenant {
				continue
			}
			id, err := NewID()
			if err != nil {
				return err
			}
			f.ID, f.TenantID, f.State, f.CreatedAt, f.UpdatedAt = id, tenant, StateProposed, now, now
			draft, evidence, err := encode(f)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO iris_learning_proposals (tenant_id, `+pgCols+`)
			    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'',NULL,'',NULL,'','',0,$12,$12)`,
				tenant, f.ID, string(f.Target), string(f.Generator), f.Subject, f.Title, f.Why, draft, evidence,
				f.EvidenceCount, string(f.State), now); err != nil {
				return fmt.Errorf("insert: %w", err)
			}
			total++
			open++
			added++
		}
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("irislearning: offer: %w", err)
	}
	return added, refreshed, nil
}

func update(ctx context.Context, tx pgx.Tx, tenant string, p Proposal) error {
	draft, evidence, err := encode(p)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE iris_learning_proposals SET title = $3, why = $4, draft = $5, evidence = $6,
	    evidence_count = $7, state = $8, adopted_by = $9, adopted_at = $10, decided_by = $11, decided_at = $12,
	    reason = $13, target_id = $14, target_version = $15, updated_at = $16
	    WHERE tenant_id = $1 AND id = $2`,
		tenant, p.ID, p.Title, p.Why, draft, evidence, p.EvidenceCount, string(p.State), p.AdoptedBy, p.AdoptedAt,
		p.DecidedBy, p.DecidedAt, p.Reason, p.TargetID, p.TargetVersion, p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	return nil
}

// Update implements Store.
func (s *PGStore) Update(ctx context.Context, tenant, id string, fn func(*Proposal) error) (Proposal, error) {
	if !ValidID(id) {
		return Proposal{}, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out Proposal
	err := s.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		cur, err := scanProposal(tx.QueryRow(ctx, `SELECT `+pgCols+` FROM iris_learning_proposals
		    WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenant, id), tenant)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		next := clone(cur)
		if err := fn(&next); err != nil {
			return err
		}
		next.ID, next.TenantID = cur.ID, cur.TenantID
		if err := update(ctx, tx, tenant, next); err != nil {
			return err
		}
		out = next
		return nil
	})
	if err != nil {
		var sentinel = []error{ErrNotFound, ErrWrongState, ErrSelfApproval, ErrInvalid}
		for _, e := range sentinel {
			if errors.Is(err, e) {
				return Proposal{}, err
			}
		}
		return Proposal{}, fmt.Errorf("irislearning: update: %w", err)
	}
	return out, nil
}

var _ Store = (*PGStore)(nil)
var _ Store = (*MemStore)(nil)
