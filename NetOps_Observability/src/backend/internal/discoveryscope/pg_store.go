// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discoveryscope

// pg_store.go — the Postgres backend (migration 0067_discovery_scopes.sql).
//
// ISOLATION. discovery_scopes is FORCE-RLS tenant_iso (the 0063 predicate).
// Every statement runs under WithTenant: a scoped read or write as (tenant,
// cross=false), so WITH CHECK refuses a row filed under another tenant and USING
// hides every other tenant's rows even from a query that forgets its WHERE. The
// cross-tenant read ('*') is the platform owner's list and the boot snapshot.
//
// BOUNDS (§9). Each call has its own deadline; the table is bounded by
// MaxPerTenant / MaxTotal, checked in the write transaction.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DB is the injected relational seam (platformdb.DB satisfies it).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

const pgTimeout = 10 * time.Second

// PGStore is the Postgres Store.
type PGStore struct{ db DB }

// NewPGStore builds the Postgres backend.
func NewPGStore(db DB) *PGStore { return &PGStore{db: db} }

const selectCols = `tenant_id, id, name, ranges, allow_non_private, credential_refs, enabled, created_by, created_at, updated_at`

func scanScope(row pgx.Row) (Scope, error) {
	var sc Scope
	var ranges, refs []byte
	if err := row.Scan(&sc.TenantID, &sc.ID, &sc.Name, &ranges, &sc.AllowNonPrivate, &refs, &sc.Enabled,
		&sc.CreatedBy, &sc.CreatedAt, &sc.UpdatedAt); err != nil {
		return Scope{}, err
	}
	if err := json.Unmarshal(ranges, &sc.Ranges); err != nil {
		return Scope{}, fmt.Errorf("discovery_scopes %s/%s ranges: %w", sc.TenantID, sc.ID, err)
	}
	if err := json.Unmarshal(refs, &sc.CredentialRefs); err != nil {
		return Scope{}, fmt.Errorf("discovery_scopes %s/%s credential_refs: %w", sc.TenantID, sc.ID, err)
	}
	sc.CreatedAt, sc.UpdatedAt = sc.CreatedAt.UTC(), sc.UpdatedAt.UTC()
	if err := Validate(&sc); err != nil {
		return Scope{}, fmt.Errorf("discovery_scopes row %s/%s: %w", sc.TenantID, sc.ID, err)
	}
	return sc, nil
}

// List implements Store.
func (s *PGStore) List(ctx context.Context, tenant string, cross bool) ([]Scope, error) {
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out []Scope
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		out = out[:0]
		// The WHERE is belt-and-braces beside RLS.
		q := `SELECT ` + selectCols + ` FROM discovery_scopes`
		var args []any
		if !cross {
			q += ` WHERE tenant_id = $1`
			args = append(args, NormTenant(tenant))
		}
		q += ` ORDER BY tenant_id, id`
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			sc, err := scanScope(rows)
			if err != nil {
				return err
			}
			out = append(out, sc)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("read discovery_scopes: %w", err)
	}
	return out, nil
}

// Get implements Store.
func (s *PGStore) Get(ctx context.Context, tenant string, cross bool, id string) (Scope, bool, error) {
	if !ValidID(id) {
		return Scope{}, false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var sc Scope
	found := false
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		q := `SELECT ` + selectCols + ` FROM discovery_scopes WHERE id = $1`
		args := []any{id}
		if !cross {
			q += ` AND tenant_id = $2`
			args = append(args, NormTenant(tenant))
		}
		got, err := scanScope(tx.QueryRow(ctx, q, args...))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		sc, found = got, true
		return nil
	})
	if err != nil {
		return Scope{}, false, fmt.Errorf("read discovery_scopes: %w", err)
	}
	return sc, found, nil
}

// Put implements Store: one transaction scoped to the scope's own tenant.
func (s *PGStore) Put(ctx context.Context, sc Scope) error {
	if err := Validate(&sc); err != nil {
		return err
	}
	ranges, err := json.Marshal(sc.Ranges)
	if err != nil {
		return fmt.Errorf("encode ranges: %w", err)
	}
	refs, err := json.Marshal(sc.CredentialRefs)
	if err != nil {
		return fmt.Errorf("encode credential refs: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	err = s.db.WithTenant(ctx, sc.TenantID, false, func(tx pgx.Tx) error {
		var mine int
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE id <> $2), COALESCE(bool_or(id = $2), false) FROM discovery_scopes WHERE tenant_id = $1`,
			sc.TenantID, sc.ID).Scan(&mine, &exists); err != nil {
			return err
		}
		if !exists && mine >= MaxPerTenant {
			return fmt.Errorf("%w: at most %d scans per customer", ErrInvalid, MaxPerTenant)
		}
		// UNIQUE (id) refuses an id another tenant holds: a scope is never
		// moved between tenants, not even by a colliding id.
		_, err := tx.Exec(ctx, `
INSERT INTO discovery_scopes (tenant_id, id, name, ranges, allow_non_private, credential_refs, enabled, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4::jsonb, $5, $6::jsonb, $7, $8, $9, $10)
ON CONFLICT (tenant_id, id) DO UPDATE SET
   name = EXCLUDED.name, ranges = EXCLUDED.ranges, allow_non_private = EXCLUDED.allow_non_private,
   credential_refs = EXCLUDED.credential_refs, enabled = EXCLUDED.enabled, updated_at = EXCLUDED.updated_at`,
			sc.TenantID, sc.ID, sc.Name, string(ranges), sc.AllowNonPrivate, string(refs), sc.Enabled,
			sc.CreatedBy, sc.CreatedAt.UTC(), sc.UpdatedAt.UTC())
		return err
	})
	if err != nil {
		return fmt.Errorf("write discovery_scopes: %w", err)
	}
	return nil
}

// Delete implements Store.
func (s *PGStore) Delete(ctx context.Context, tenant, id string) (bool, error) {
	if !ValidID(id) {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	removed := false
	err := s.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM discovery_scopes WHERE tenant_id = $1 AND id = $2`, NormTenant(tenant), id)
		if err != nil {
			return err
		}
		removed = tag.RowsAffected() > 0
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("delete discovery_scopes: %w", err)
	}
	return removed, nil
}
