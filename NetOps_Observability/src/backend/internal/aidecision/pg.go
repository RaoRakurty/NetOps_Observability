// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aidecision

// pg.go — the Postgres store over ai_decision_ledger (migration 0056). Every
// statement runs inside WithTenant: an Append in exactly the writer's tenant
// (cross=false), so the FORCE-RLS tenant_iso WITH CHECK refuses a row for any
// other; a List in the reader's tenant, or across tenants ('*') for the
// platform owner. There is no UPDATE or DELETE statement here, and the
// database would refuse one (no grant; a trigger).

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DB is the injected relational seam (the investigation-memory idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// PGStore is the Postgres Store.
type PGStore struct {
	db  DB
	now func() time.Time
}

// NewPGStore builds the Postgres store.
func NewPGStore(db DB) *PGStore {
	return &PGStore{db: db, now: func() time.Time { return time.Now().UTC() }}
}

const pgTimeout = 5 * time.Second

// Append writes one decision's entries in one transaction.
func (p *PGStore) Append(ctx context.Context, tenant string, entries []Entry) error {
	es, err := NormalizeBatch(tenant, entries, p.now())
	if err != nil || len(es) == 0 {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	err = p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		for _, e := range es {
			b.Queue(`INSERT INTO ai_decision_ledger (tenant_id, id, decision_id, seq, event_type, principal_sub,
			        surface, created_at, incident_ref, intent, mode, skill, tool, tool_version, model_provider,
			        model_name, model_tier, args_sha256, result_sha256, item_count, outcome, answer_id, query_log_id)
			    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
			        $20, $21, $22, $23)`,
				e.TenantID, e.ID, e.DecisionID, e.Seq, e.EventType, e.Principal, e.Surface, e.At, e.IncidentRef,
				e.Intent, e.Mode, e.Skill, e.Tool, e.ToolVersion, e.ModelProvider, e.ModelName, e.ModelTier,
				e.ArgsSHA256, e.ResultSHA256, e.ItemCount, e.Outcome, e.AnswerID, e.QueryLogID)
		}
		return tx.SendBatch(ctx, b).Close()
	})
	if err != nil {
		return fmt.Errorf("aidecision: append: %w", err)
	}
	return nil
}

const pgColumns = `tenant_id, id::text, decision_id::text, seq, event_type, principal_sub, surface, created_at,
        incident_ref, intent, mode, skill, tool, tool_version, model_provider, model_name, model_tier,
        args_sha256, result_sha256, item_count, outcome, answer_id, query_log_id`

// List returns entries newest first; one decision's steps come in seq order.
func (p *PGStore) List(ctx context.Context, tenant string, cross bool, f ListFilter) ([]Entry, error) {
	if f.DecisionID != "" && !ValidID(f.DecisionID) {
		return []Entry{}, nil
	}
	limit := clampLimit(f.Limit)
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	out := []Entry{}
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		// The tenant predicate repeats what RLS enforces (a scoped reader); the
		// platform owner's '*' view drops it ($2 = true) and RLS admits all.
		var before *time.Time
		if !f.Before.IsZero() {
			b := f.Before.UTC()
			before = &b
		}
		var rows pgx.Rows
		var err error
		if f.DecisionID == "" {
			rows, err = tx.Query(ctx, `SELECT `+pgColumns+` FROM ai_decision_ledger
			    WHERE ($2::bool OR tenant_id = $1::text)
			      AND ($3::timestamptz IS NULL OR created_at < $3::timestamptz)
			    ORDER BY created_at DESC, decision_id, seq DESC LIMIT $4::int`, tenant, cross, before, limit)
		} else {
			rows, err = tx.Query(ctx, `SELECT `+pgColumns+` FROM ai_decision_ledger
			    WHERE ($2::bool OR tenant_id = $1::text) AND decision_id = $3::uuid
			      AND ($4::timestamptz IS NULL OR created_at < $4::timestamptz)
			    ORDER BY seq ASC LIMIT $5::int`, tenant, cross, f.DecisionID, before, limit)
		}
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e Entry
			if err := rows.Scan(&e.TenantID, &e.ID, &e.DecisionID, &e.Seq, &e.EventType, &e.Principal, &e.Surface,
				&e.At, &e.IncidentRef, &e.Intent, &e.Mode, &e.Skill, &e.Tool, &e.ToolVersion, &e.ModelProvider,
				&e.ModelName, &e.ModelTier, &e.ArgsSHA256, &e.ResultSHA256, &e.ItemCount, &e.Outcome, &e.AnswerID,
				&e.QueryLogID); err != nil {
				return err
			}
			e.At = e.At.UTC()
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("aidecision: list: %w", err)
	}
	return out, nil
}

var _ Store = (*PGStore)(nil)
