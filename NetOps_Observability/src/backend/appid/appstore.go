// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

// appid_store.go — Application Identification registry (#81 P0). An "application"
// is a THIN PARENT over the #69 technical services (services.application_id links
// up; we don't rebuild #69). The catalog (app_catalog) + the P1 LPM-trie resolver
// land later; P0 ships the registry + the verdict contract (appid/verdict.go).
//
// Two backends like every other store: in-memory (default, tenant-filtered IN the
// store) and Postgres (tenant_iso FORCE-RLS via withTenant). Tenant isolation is
// enforced in the store itself (CLAUDE.md §3a) — no caller reads across tenants.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"crypto/rand"
	"fmt"
	"github.com/jackc/pgx/v5"
)

var validAppCriticality = map[string]bool{"critical": true, "high": true, "normal": true, "low": true}

// Application — a business capability. owner_team powers owner=app_team RCA
// attribution. Archive (never hard-delete): attribution history references the id.
type Application struct {
	ApplicationID string     `json:"application_id"`
	TenantID      string     `json:"tenant_id"`
	Name          string     `json:"name"`
	OwnerTeam     string     `json:"owner_team"`
	Criticality   string     `json:"criticality"`
	Description   string     `json:"description"`
	CreatedAt     time.Time  `json:"created_at"`
	ArchivedAt    *time.Time `json:"archived_at,omitempty"`
}

// ValidateApplicationInput is a pure guard (unit-tested) for create.
func ValidateApplicationInput(name, criticality string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("application name is required")
	}
	if len(name) > 120 {
		return errors.New("application name too long (max 120)")
	}
	if criticality != "" && !validAppCriticality[criticality] {
		return errors.New("criticality must be one of critical|high|normal|low")
	}
	return nil
}

type AppStore interface {
	List(ctx context.Context, tenant string, cross bool, includeArchived bool) ([]Application, error)
	Get(ctx context.Context, tenant string, cross bool, id string) (Application, bool, error)
	Create(ctx context.Context, tenant string, cross bool, in Application) (Application, error)
	Archive(ctx context.Context, tenant string, cross bool, id string) (bool, error)
}

// ── in-memory backend ──────────────────────────────────────────────────────────

// DB is the injected relational seam (the portintel.DB idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// NewMemAppStore / NewPGAppStore build the two backends.
func NewMemAppStore() *memAppStore { return &memAppStore{by: map[string]Application{}} }

func NewPGAppStore(db DB) *pgAppStore { return &pgAppStore{db: db} }

// normTenant / newUUIDv4 mirror the integrator's helpers (duplicated per the
// no-shared-utils rule).
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

type memAppStore struct {
	mu sync.RWMutex
	by map[string]Application // key: tenant\x1fapplication_id
}

func (m *memAppStore) key(tenant, id string) string {
	return normTenant(tenant) + "\x1f" + id
}

func (m *memAppStore) List(_ context.Context, tenant string, cross bool, includeArchived bool) ([]Application, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t := normTenant(tenant)
	out := []Application{}
	for _, a := range m.by {
		if !cross && a.TenantID != t { // default-closed tenant filter
			continue
		}
		if !includeArchived && a.ArchivedAt != nil {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func (m *memAppStore) Get(_ context.Context, tenant string, cross bool, id string) (Application, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t := normTenant(tenant)
	for _, a := range m.by {
		if a.ApplicationID != id {
			continue
		}
		if !cross && a.TenantID != t { // cross-tenant get → not found (never reveal another tenant's id)
			return Application{}, false, nil
		}
		return a, true, nil
	}
	return Application{}, false, nil
}

func (m *memAppStore) Create(_ context.Context, _ string, _ bool, in Application) (Application, error) {
	id, err := newUUIDv4()
	if err != nil {
		return Application{}, err
	}
	in.ApplicationID = id
	if in.Criticality == "" {
		in.Criticality = "normal"
	}
	in.CreatedAt = time.Now().UTC()
	in.TenantID = normTenant(in.TenantID)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.by[m.key(in.TenantID, id)] = in
	return in, nil
}

func (m *memAppStore) Archive(_ context.Context, tenant string, cross bool, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := normTenant(tenant)
	for k, a := range m.by {
		if a.ApplicationID != id {
			continue
		}
		if !cross && a.TenantID != t { // can't archive another tenant's app
			return false, nil
		}
		if a.ArchivedAt != nil {
			return false, nil
		}
		now := time.Now().UTC()
		a.ArchivedAt = &now
		m.by[k] = a
		return true, nil
	}
	return false, nil
}

// ── Postgres backend (tenant_iso FORCE-RLS via withTenant) ──────────────────────

type pgAppStore struct{ db DB }

func (st *pgAppStore) List(ctx context.Context, tenant string, cross bool, includeArchived bool) ([]Application, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := make([]Application, 0)
	q := `SELECT application_id, tenant_id, name, owner_team, criticality, description, created_at, archived_at
            FROM applications`
	if !includeArchived {
		q += ` WHERE archived_at IS NULL`
	}
	q += ` ORDER BY created_at DESC`
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a Application
			if err := rows.Scan(&a.ApplicationID, &a.TenantID, &a.Name, &a.OwnerTeam, &a.Criticality, &a.Description, &a.CreatedAt, &a.ArchivedAt); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func (st *pgAppStore) Get(ctx context.Context, tenant string, cross bool, id string) (Application, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var a Application
	found := false
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT application_id, tenant_id, name, owner_team, criticality, description, created_at, archived_at
              FROM applications WHERE application_id = $1`, id)
		e := row.Scan(&a.ApplicationID, &a.TenantID, &a.Name, &a.OwnerTeam, &a.Criticality, &a.Description, &a.CreatedAt, &a.ArchivedAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		found = true
		return nil
	})
	return a, found, err
}

func (st *pgAppStore) Create(ctx context.Context, tenant string, cross bool, in Application) (Application, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	id, err := newUUIDv4()
	if err != nil {
		return Application{}, err
	}
	in.ApplicationID = id
	if in.Criticality == "" {
		in.Criticality = "normal"
	}
	err = st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `INSERT INTO applications (application_id, tenant_id, name, owner_team, criticality, description)
              VALUES ($1,$2,$3,$4,$5,$6) RETURNING created_at`,
			in.ApplicationID, in.TenantID, in.Name, in.OwnerTeam, in.Criticality, in.Description)
		return row.Scan(&in.CreatedAt)
	})
	return in, err
}

func (st *pgAppStore) Archive(ctx context.Context, tenant string, cross bool, id string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	affected := false
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `UPDATE applications SET archived_at = now() WHERE application_id = $1 AND archived_at IS NULL`, id)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected() > 0
		return nil
	})
	return affected, err
}
