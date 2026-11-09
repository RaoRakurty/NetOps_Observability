// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package srcauthority

// pg.go — the Postgres store over iris_source_authority (migration 0065).
// Every statement runs inside WithTenant(tenant, cross=false) under the
// FORCE-RLS tenant_iso policy, and tenant_id is ALSO filtered explicitly; the
// database CHECKs the order is a permutation of the four classes, so a row
// that bypassed the application still cannot hold an undefined order.

import (
	"context"
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
type PGStore struct {
	db  DB
	now func() time.Time
}

// NewPGStore builds the Postgres store.
func NewPGStore(db DB) *PGStore {
	return &PGStore{db: db, now: func() time.Time { return time.Now().UTC() }}
}

const pgTimeout = 5 * time.Second

func classesToText(order []Class) []string {
	out := make([]string, len(order))
	for i, c := range order {
		out[i] = string(c)
	}
	return out
}

// Get implements Store. A stored order is returned as stored; Effective
// re-validates it before use.
func (p *PGStore) Get(ctx context.Context, tenant string) (Policy, bool, error) {
	if tenant == "" {
		return Policy{}, false, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var (
		pol   Policy
		order []string
		found bool
	)
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT source_order, updated_by, updated_at FROM iris_source_authority WHERE tenant_id = $1::text`, tenant).
			Scan(&order, &pol.UpdatedBy, &pol.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return Policy{}, false, fmt.Errorf("srcauthority: get: %w", err)
	}
	if !found {
		return Policy{}, false, nil
	}
	pol.Tenant = tenant
	for _, s := range order {
		pol.Order = append(pol.Order, Class(s))
	}
	pol.UpdatedAt = pol.UpdatedAt.UTC()
	return pol, true, nil
}

// Put implements Store (an upsert on the tenant's one row).
func (p *PGStore) Put(ctx context.Context, tenant, actor string, order []Class) (Policy, error) {
	if err := checkPut(tenant, actor, order); err != nil {
		return Policy{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	now := p.now()
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO iris_source_authority (tenant_id, source_order, updated_by, updated_at)
		    VALUES ($1::text, $2::text[], $3::text, $4)
		    ON CONFLICT (tenant_id) DO UPDATE SET source_order = EXCLUDED.source_order,
		        updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
			tenant, classesToText(order), actor, now)
		return err
	})
	if err != nil {
		return Policy{}, fmt.Errorf("srcauthority: put: %w", err)
	}
	return Policy{Tenant: tenant, Order: append([]Class(nil), order...), UpdatedBy: actor, UpdatedAt: now}, nil
}

// Delete implements Store.
func (p *PGStore) Delete(ctx context.Context, tenant string) error {
	if tenant == "" {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM iris_source_authority WHERE tenant_id = $1::text`, tenant)
		return err
	})
	if err != nil {
		return fmt.Errorf("srcauthority: delete: %w", err)
	}
	return nil
}
