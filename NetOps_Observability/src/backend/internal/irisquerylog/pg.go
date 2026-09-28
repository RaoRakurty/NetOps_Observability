// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisquerylog

// pg.go — the Postgres store over iris_query_log (migration 0054). Every
// statement runs inside WithTenant(tenant, cross=false), so the FORCE-RLS
// tenant_iso policy confines it to the principal's tenant; principal_sub is
// filtered explicitly on top where a statement is about one person.

import (
	"context"
	"encoding/json"
	"errors"
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

// Record stores one record, pruning the tenant's expired records and, past
// MaxPerTenant, its oldest ones, in the same transaction.
func (p *PGStore) Record(ctx context.Context, tenant string, r Record) (Record, error) {
	now := p.now()
	r, err := Normalize(tenant, r, now)
	if err != nil {
		return Record{}, err
	}
	codes, err := json.Marshal(r.ValidationCodes)
	if err != nil {
		return Record{}, fmt.Errorf("irisquerylog: encode codes: %w", err)
	}
	ents, err := json.Marshal(r.Entities)
	if err != nil {
		return Record{}, fmt.Errorf("irisquerylog: encode entities: %w", err)
	}
	var conv *string
	if r.ConversationID != "" {
		conv = &r.ConversationID
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	err = p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM iris_query_log WHERE tenant_id = $1::text AND created_at < $2::timestamptz`,
			tenant, now.Add(-Retention)); err != nil {
			return fmt.Errorf("prune expired: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM iris_query_log WHERE tenant_id = $1::text AND id IN (
		        SELECT id FROM iris_query_log WHERE tenant_id = $1::text
		         ORDER BY created_at DESC, id ASC OFFSET $2::int)`,
			tenant, MaxPerTenant-1); err != nil {
			return fmt.Errorf("prune cap: %w", err)
		}
		_, err := tx.Exec(ctx, `INSERT INTO iris_query_log (tenant_id, id, principal_sub, conversation_id, source,
		        created_at, question, intent, outcome, query_type, ast_hash, catalog_version,
		        validation_codes, entities, row_count, series_count, duration_ms, corrections)
		    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14::jsonb, $15, $16, $17, '[]'::jsonb)`,
			tenant, r.ID, r.Principal, conv, r.Source, r.At, r.Question, r.Intent, r.Outcome, r.QueryType,
			r.ASTHash, r.CatalogVersion, string(codes), string(ents), r.Rows, r.Series, r.DurationMs)
		return err
	})
	if err != nil {
		return Record{}, fmt.Errorf("irisquerylog: record: %w", err)
	}
	return r, nil
}

const pgColumns = `id::text, principal_sub, COALESCE(conversation_id::text, ''), source, created_at, question, intent,
        outcome, query_type, ast_hash, catalog_version, validation_codes, entities, row_count, series_count,
        duration_ms, corrections`

// List returns the tenant's live records, newest first.
func (p *PGStore) List(ctx context.Context, tenant string, f ListFilter) ([]Record, error) {
	limit := clampLimit(f.Limit)
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	out := []Record{}
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pgColumns+` FROM iris_query_log
		    WHERE tenant_id = $1::text AND created_at >= $2::timestamptz
		      AND ($3::text = '' OR principal_sub = $3::text)
		    ORDER BY created_at DESC, id ASC LIMIT $4::int`,
			tenant, p.now().Add(-Retention), f.Principal, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRecord(rows, tenant)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("irisquerylog: list: %w", err)
	}
	return out, nil
}

// Correct attaches a correction to the principal's own live record, under a
// row lock so two concurrent corrections cannot both pass the cap.
func (p *PGStore) Correct(ctx context.Context, tenant, principal, id string, c Correction) (Record, error) {
	now := p.now()
	c, err := NormalizeCorrection(c, now)
	if err != nil {
		return Record{}, err
	}
	if !ValidID(id) || principal == "" {
		return Record{}, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out Record
	err = p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+pgColumns+` FROM iris_query_log
		    WHERE tenant_id = $1::text AND id = $2::uuid AND principal_sub = $3::text
		      AND created_at >= $4::timestamptz FOR UPDATE`, tenant, id, principal, now.Add(-Retention))
		r, err := scanRecord(row, tenant)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if len(r.Corrections) >= MaxCorrections {
			return ErrFull
		}
		r.Corrections = append(r.Corrections, c)
		enc, err := json.Marshal(r.Corrections)
		if err != nil {
			return fmt.Errorf("encode corrections: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE iris_query_log SET corrections = $4::jsonb
		    WHERE tenant_id = $1::text AND id = $2::uuid AND principal_sub = $3::text`,
			tenant, id, principal, string(enc)); err != nil {
			return err
		}
		out = r
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrFull) {
			return Record{}, err
		}
		return Record{}, fmt.Errorf("irisquerylog: correct: %w", err)
	}
	return out, nil
}

// scanRecord reads one row. What the database returns is re-bounded: the
// store does not trust it to still hold what was written.
func scanRecord(row pgx.Row, tenant string) (Record, error) {
	var r Record
	var codes, ents, corr []byte
	if err := row.Scan(&r.ID, &r.Principal, &r.ConversationID, &r.Source, &r.At, &r.Question, &r.Intent,
		&r.Outcome, &r.QueryType, &r.ASTHash, &r.CatalogVersion, &codes, &ents, &r.Rows, &r.Series,
		&r.DurationMs, &corr); err != nil {
		return Record{}, err
	}
	r.TenantID = tenant
	if err := json.Unmarshal(codes, &r.ValidationCodes); err != nil {
		return Record{}, fmt.Errorf("irisquerylog: stored codes unreadable: %w", err)
	}
	if err := json.Unmarshal(ents, &r.Entities); err != nil {
		return Record{}, fmt.Errorf("irisquerylog: stored entities unreadable: %w", err)
	}
	if err := json.Unmarshal(corr, &r.Corrections); err != nil {
		return Record{}, fmt.Errorf("irisquerylog: stored corrections unreadable: %w", err)
	}
	r.ValidationCodes = boundedCodes(r.ValidationCodes)
	r.Entities = boundedEntities(r.Entities)
	if len(r.Corrections) > MaxCorrections {
		r.Corrections = r.Corrections[:MaxCorrections]
	}
	if r.Corrections == nil {
		r.Corrections = []Correction{}
	}
	return r, nil
}

var _ Store = (*PGStore)(nil)
