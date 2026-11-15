// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisaction

// pg.go — the Postgres store over iris_action_requests (migration 0076). Every
// statement runs inside WithTenant(tenant, cross=false) under the FORCE-RLS
// tenant_iso policy; tenant_id is also filtered explicitly. Insert counts the
// open requests under a transaction-scoped advisory lock on the tenant so two
// concurrent proposals cannot both pass the cap; Update loads the row
// FOR UPDATE, which is what makes the approval claim a compare-and-set across
// API replicas. The table's CHECKs refuse what the code would not do (a write
// decided by its proposer, a write on a dry run, a decline without a reason).

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

const pgCols = `id, kind, status, policy, proposed_by, proposed_via, decision_id, correlation_id, citations,
    payload, summary, preview, dry_run, created_at, expires_at, decided_by, decided_at, reason, executed_at, result`

func scanRequest(row pgx.Row, tenant string) (Request, error) {
	var (
		r                               Request
		kind, status, policy            string
		citations, payload, dry, result []byte
		decidedAt, executedAt           *time.Time
	)
	if err := row.Scan(&r.ID, &kind, &status, &policy, &r.ProposedBy, &r.ProposedVia, &r.DecisionID, &r.CorrelationID,
		&citations, &payload, &r.Summary, &r.Preview, &dry, &r.CreatedAt, &r.ExpiresAt,
		&r.DecidedBy, &decidedAt, &r.Reason, &executedAt, &result); err != nil {
		return Request{}, err
	}
	r.TenantID, r.Kind, r.Status, r.Policy = tenant, Kind(kind), Status(status), Decision(policy)
	if err := json.Unmarshal(citations, &r.Citations); err != nil {
		return Request{}, fmt.Errorf("citations: %w", err)
	}
	if r.Citations == nil {
		r.Citations = []string{}
	}
	r.Payload = append(json.RawMessage(nil), payload...)
	if err := json.Unmarshal(dry, &r.DryRun); err != nil {
		return Request{}, fmt.Errorf("dry_run: %w", err)
	}
	if len(result) > 0 {
		var res Result
		if err := json.Unmarshal(result, &res); err != nil {
			return Request{}, fmt.Errorf("result: %w", err)
		}
		r.Result = &res
	}
	if decidedAt != nil {
		t := decidedAt.UTC()
		r.DecidedAt = &t
	}
	if executedAt != nil {
		t := executedAt.UTC()
		r.ExecutedAt = &t
	}
	r.CreatedAt, r.ExpiresAt = r.CreatedAt.UTC(), r.ExpiresAt.UTC()
	return r, nil
}

func encodeRequest(r Request) (citations, dry, result []byte, err error) {
	cs := r.Citations
	if cs == nil {
		cs = []string{}
	}
	if citations, err = json.Marshal(cs); err != nil {
		return nil, nil, nil, err
	}
	if dry, err = json.Marshal(r.DryRun); err != nil {
		return nil, nil, nil, err
	}
	if r.Result != nil {
		if result, err = json.Marshal(r.Result); err != nil {
			return nil, nil, nil, err
		}
	}
	return citations, dry, result, nil
}

func (p *PGStore) tx(ctx context.Context, tenant string, fn func(pgx.Tx) error) error {
	if tenant == "" || tenant == "*" {
		return fmt.Errorf("%w: a single workspace is required", ErrInvalid)
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	return p.db.WithTenant(ctx, tenant, false, fn)
}

// Insert implements Store.
func (p *PGStore) Insert(ctx context.Context, r Request) error {
	if r.TenantID == "" || r.ID == "" {
		return fmt.Errorf("%w: tenant and id are required", ErrInvalid)
	}
	citations, dry, result, err := encodeRequest(r)
	if err != nil {
		return err
	}
	return p.tx(ctx, r.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('iris_action_requests:' || $1))`, r.TenantID); err != nil {
			return err
		}
		if r.Status == StatusProposed {
			var open int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM iris_action_requests WHERE tenant_id = $1 AND status = 'proposed'`,
				r.TenantID).Scan(&open); err != nil {
				return err
			}
			if open >= MaxOpenPerTenant {
				return ErrTooManyOpen
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO iris_action_requests (tenant_id, `+pgCols+`)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
			r.TenantID, r.ID, string(r.Kind), string(r.Status), string(r.Policy), r.ProposedBy, r.ProposedVia,
			r.DecisionID, r.CorrelationID, citations, []byte(r.Payload), r.Summary, r.Preview, dry,
			r.CreatedAt, r.ExpiresAt, r.DecidedBy, r.DecidedAt, r.Reason, r.ExecutedAt, result); err != nil {
			return err
		}
		// Evict the oldest TERMINAL rows past the cap; open rows are never evicted.
		_, err := tx.Exec(ctx, `DELETE FROM iris_action_requests WHERE tenant_id = $1 AND id IN (
                SELECT id FROM iris_action_requests
                 WHERE tenant_id = $1 AND status IN ('dry_run','executed','failed','rejected','expired')
                 ORDER BY created_at ASC
                 LIMIT GREATEST((SELECT count(*) FROM iris_action_requests WHERE tenant_id = $1) - $2, 0))`,
			r.TenantID, MaxRequestsPerTenant)
		return err
	})
}

// Get implements Store.
func (p *PGStore) Get(ctx context.Context, tenant, id string) (Request, error) {
	var r Request
	err := p.tx(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		r, err = scanRequest(tx.QueryRow(ctx, `SELECT `+pgCols+` FROM iris_action_requests WHERE tenant_id = $1 AND id::text = $2`,
			tenant, id), tenant)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Request{}, ErrNotFound
	}
	return r, err
}

// List implements Store.
func (p *PGStore) List(ctx context.Context, tenant string, f Filter) ([]Request, error) {
	out := []Request{}
	err := p.tx(ctx, tenant, func(tx pgx.Tx) error {
		q := `SELECT ` + pgCols + ` FROM iris_action_requests WHERE tenant_id = $1`
		args := []any{tenant}
		if f.Status != "" {
			q += ` AND status = $2`
			args = append(args, string(f.Status))
		}
		q += fmt.Sprintf(` ORDER BY created_at DESC LIMIT %d`, clampLimit(f.Limit))
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRequest(rows, tenant)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// Update implements Store.
func (p *PGStore) Update(ctx context.Context, tenant, id string, expect Status, fn func(*Request) error) (Request, error) {
	var (
		final   Request
		pending bool
	)
	err := p.tx(ctx, tenant, func(tx pgx.Tx) error {
		cur, err := scanRequest(tx.QueryRow(ctx, `SELECT `+pgCols+` FROM iris_action_requests
            WHERE tenant_id = $1 AND id::text = $2 FOR UPDATE`, tenant, id), tenant)
		if err != nil {
			return err
		}
		if cur.Status != expect {
			final, pending = cur, true
			return nil
		}
		next := cloneReq(cur)
		if err := fn(&next); err != nil {
			final = cur
			return err
		}
		citations, dry, result, err := encodeRequest(next)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE iris_action_requests SET status = $3, decided_by = $4, decided_at = $5,
                reason = $6, executed_at = $7, result = $8, citations = $9, dry_run = $10
             WHERE tenant_id = $1 AND id::text = $2`,
			tenant, id, string(next.Status), next.DecidedBy, next.DecidedAt, next.Reason, next.ExecutedAt, result,
			citations, dry); err != nil {
			return err
		}
		final = next
		return nil
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return Request{}, ErrNotFound
	case err != nil:
		return final, err
	case pending:
		return final, ErrNotPending
	}
	return final, nil
}
