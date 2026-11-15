// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package evalconsent records who agreed to share their Iris questions with
// their workspace's eval set (tracker 337 N-H3, consented pooling).
//
// DECISION (owner-delegated, 2026-11-15). A colleague's typed question is
// theirs: the query log and the triage view withhold it from everyone else.
// Pooling questions across a workspace makes the field eval far more useful,
// so it is offered per person, OPT-IN, DEFAULT OFF and REVOCABLE:
//   - consent is per (tenant, person); nobody can grant it for someone else;
//   - without it, an export holds only the exporting admin's own questions
//     (the behaviour before this package);
//   - with it, the person's questions join their OWN workspace's candidates
//     export, marked pooled and never named — never another workspace's;
//   - revoking takes effect at the next export: the export reads consent at
//     export time, so nothing already revoked is ever pooled again (what an
//     admin already downloaded is outside the server, and the UI says so);
//   - every grant and revoke is written to the audit log by the caller.
//
// Isolation (§3a rule 4) is in the store: Postgres by the tenant_iso FORCE-RLS
// policy plus an explicit tenant filter (migration 0077); memory by a
// tenant-keyed map. No method reads across tenants.
package evalconsent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Consent is one person's current choice. The zero value means never asked,
// which is the same as declined.
type Consent struct {
	Consented bool      `json:"consented"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// Store holds consent per (tenant, principal).
type Store interface {
	// Get returns principal's consent in tenant (zero when never set).
	Get(ctx context.Context, tenant, principal string) (Consent, error)
	// Set records principal's choice in tenant.
	Set(ctx context.Context, tenant, principal string, on bool, now time.Time) (Consent, error)
	// Consenting returns the principals of tenant who consent now.
	Consenting(ctx context.Context, tenant string) (map[string]bool, error)
}

// ErrInvalid is a missing tenant or principal.
var ErrInvalid = errors.New("evalconsent: tenant and principal are required")

func valid(tenant, principal string) bool {
	return strings.TrimSpace(tenant) != "" && strings.TrimSpace(principal) != "" &&
		len(tenant) <= 128 && len(principal) <= 256
}

// MemStore is the store without Postgres (lost on restart, like the query log
// it gates on that build).
type MemStore struct {
	mu   sync.Mutex
	rows map[string]map[string]Consent // tenant → principal → consent
}

// NewMemStore returns an empty memory store.
func NewMemStore() *MemStore { return &MemStore{rows: map[string]map[string]Consent{}} }

// Get implements Store.
func (m *MemStore) Get(_ context.Context, tenant, principal string) (Consent, error) {
	if !valid(tenant, principal) {
		return Consent{}, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rows[tenant][principal], nil
}

// Set implements Store.
func (m *MemStore) Set(_ context.Context, tenant, principal string, on bool, now time.Time) (Consent, error) {
	if !valid(tenant, principal) {
		return Consent{}, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows[tenant] == nil {
		m.rows[tenant] = map[string]Consent{}
	}
	c := Consent{Consented: on, UpdatedAt: now.UTC()}
	m.rows[tenant][principal] = c
	return c, nil
}

// Consenting implements Store.
func (m *MemStore) Consenting(_ context.Context, tenant string) (map[string]bool, error) {
	if strings.TrimSpace(tenant) == "" {
		return nil, ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for p, c := range m.rows[tenant] {
		if c.Consented {
			out[p] = true
		}
	}
	return out, nil
}

// DB is the Postgres seam (platformdb's tenant-scoped transaction).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type pgStore struct{ db DB }

// NewPGStore builds the Postgres store (migration 0077).
func NewPGStore(db DB) Store { return &pgStore{db: db} }

// maxConsenting bounds one Consenting read.
const maxConsenting = 10000

// Get implements Store.
func (p *pgStore) Get(ctx context.Context, tenant, principal string) (Consent, error) {
	if !valid(tenant, principal) {
		return Consent{}, ErrInvalid
	}
	var c Consent
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT consented, updated_at FROM iris_eval_consent WHERE tenant_id = $1 AND principal = $2`,
			tenant, principal).Scan(&c.Consented, &c.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			c = Consent{}
			return nil
		}
		return err
	})
	if err != nil {
		return Consent{}, fmt.Errorf("evalconsent: get: %w", err)
	}
	return c, nil
}

// Set implements Store.
func (p *pgStore) Set(ctx context.Context, tenant, principal string, on bool, now time.Time) (Consent, error) {
	if !valid(tenant, principal) {
		return Consent{}, ErrInvalid
	}
	c := Consent{Consented: on, UpdatedAt: now.UTC()}
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO iris_eval_consent (tenant_id, principal, consented, updated_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, principal) DO UPDATE SET consented = EXCLUDED.consented, updated_at = EXCLUDED.updated_at`,
			tenant, principal, c.Consented, c.UpdatedAt)
		return err
	})
	if err != nil {
		return Consent{}, fmt.Errorf("evalconsent: set: %w", err)
	}
	return c, nil
}

// Consenting implements Store.
func (p *pgStore) Consenting(ctx context.Context, tenant string) (map[string]bool, error) {
	if strings.TrimSpace(tenant) == "" {
		return nil, ErrInvalid
	}
	out := map[string]bool{}
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT principal FROM iris_eval_consent WHERE tenant_id = $1 AND consented LIMIT $2`,
			tenant, maxConsenting)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var principal string
			if err := rows.Scan(&principal); err != nil {
				return err
			}
			out[principal] = true
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("evalconsent: consenting: %w", err)
	}
	return out, nil
}
