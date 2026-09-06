// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secapi

// frameworks_store.go — WHICH COMPLIANCE FRAMEWORKS A TENANT HAS OPTED INTO.
//
// A sibling of store.go's control-plane register, deliberately kept as its OWN
// interface and its OWN backing file rather than grown onto Store: rule
// enablement and framework selection have different defaults (a detection ships
// ON, a regulatory framework ships OFF), different gates in the product story
// and different lifecycles. One interface per register keeps a future caller
// from reaching for the wrong default.
//
// Isolation is enforced IN the store (CLAUDE.md §3a rule 4): Postgres by the
// tenant_iso FORCE-RLS policy of migration 0042 through the injected WithTenant
// seam, the file backend by a tenant-keyed map. There is no unscoped "list all"
// on either.
//
// THE `configured` FLAG. "This tenant chose nothing" and "this tenant chose
// nothing ON" are different facts and must not render identically — the first
// gets the shipped default set, the second gets exactly what it asked for. So a
// save writes a row for EVERY known framework (enabled true AND false), and
// `configured` is "this tenant has at least one row".

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/platformdb"
)

// MaxFrameworkWrites bounds one selection write. The vocabulary is closed and
// small, so this is a shape guard rather than a capacity one: a body larger
// than the entire catalogue is malformed, not ambitious.
const MaxFrameworkWrites = 64

// FrameworkState is one stored per-tenant framework selection row.
type FrameworkState struct {
	FrameworkID string    `json:"framework_id"`
	Enabled     bool      `json:"enabled"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

// FrameworkStore is the per-tenant framework-selection register.
//
// `cross` is the platform-owner cross-tenant flag from principalTenant(claims);
// a non-cross caller can never observe or mutate another tenant's rows through
// any method here.
type FrameworkStore interface {
	// FrameworkStates returns the caller-visible selection as framework id →
	// enabled, plus whether the caller's scope holds ANY row at all. A false
	// `configured` means "has not chosen" and the caller applies the shipped
	// default set — it does NOT mean "everything is off".
	FrameworkStates(ctx context.Context, tenant string, cross bool) (states map[string]bool, configured bool, err error)
	// SetFrameworkStates upserts the selection. owner is the tenant the rows are
	// stamped with — derived from the authenticated principal by the handler,
	// NEVER from the request body (§3a rule 2).
	SetFrameworkStates(ctx context.Context, tenant string, cross bool, owner string, states []FrameworkState) error
}

// ---- file backend (default build; tenant-filtered IN the store) -------------

type fileFramework struct {
	TenantID    string    `json:"tenant_id"`
	FrameworkID string    `json:"framework_id"`
	Enabled     bool      `json:"enabled"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

type frameworkPayload struct {
	Frameworks []fileFramework `json:"frameworks"`
}

// FrameworkFileStore is the non-Postgres backend. Path "" keeps it purely in
// memory (tests); a real path is loaded at construction and rewritten on write.
type FrameworkFileStore struct {
	mu   sync.RWMutex
	path string
	// loadErr records a FAILED read of the state file. "The file could not be
	// read" and "this tenant has not chosen" are different facts that would
	// otherwise render identically — as the shipped default set, with no way for
	// an operator to tell that their HIPAA selection was not applied (§10 no
	// silent failures).
	loadErr error
	rows    map[string]map[string]fileFramework // tenant → framework id → row
}

// LoadErr reports why the persisted selection could not be read, or nil. The
// store still SERVES (the shipped default set) — refusing to boot over a
// preferences file would be worse — but the fact is never swallowed.
func (s *FrameworkFileStore) LoadErr() error { return s.loadErr }

// NewFrameworkFileStore loads the persisted selection.
func NewFrameworkFileStore(path string) *FrameworkFileStore {
	s := &FrameworkFileStore{path: path, rows: map[string]map[string]fileFramework{}}
	if path == "" {
		return s
	}
	b, err := platformdb.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Not an error: nobody has chosen yet. That is the normal first-boot
		// state and logging it would train operators to ignore this line.
		return s
	case err != nil:
		s.loadErr = fmt.Errorf("read security framework selection %s: %w", path, err)
		return s
	case len(b) == 0:
		return s
	}
	var p frameworkPayload
	if uerr := json.Unmarshal(b, &p); uerr != nil {
		s.loadErr = fmt.Errorf("parse security framework selection %s: %w", path, uerr)
		return s
	}
	for _, r := range p.Frameworks {
		s.putLocked(r)
	}
	return s
}

func (s *FrameworkFileStore) putLocked(r fileFramework) {
	t := NormTenant(r.TenantID)
	if s.rows[t] == nil {
		s.rows[t] = map[string]fileFramework{}
	}
	r.TenantID = t
	s.rows[t][r.FrameworkID] = r
}

// flushLocked persists the full set (call with mu held). A marshal or write
// failure is RETURNED, never swallowed.
func (s *FrameworkFileStore) flushLocked() error {
	if s.path == "" {
		return nil
	}
	p := frameworkPayload{Frameworks: []fileFramework{}}
	for _, byID := range s.rows {
		for _, r := range byID {
			p.Frameworks = append(p.Frameworks, r)
		}
	}
	sort.Slice(p.Frameworks, func(i, j int) bool {
		if p.Frameworks[i].TenantID != p.Frameworks[j].TenantID {
			return p.Frameworks[i].TenantID < p.Frameworks[j].TenantID
		}
		return p.Frameworks[i].FrameworkID < p.Frameworks[j].FrameworkID
	})
	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("encode security framework selection: %w", err)
	}
	return platformdb.Save(s.path, b)
}

func (s *FrameworkFileStore) FrameworkStates(_ context.Context, tenant string, cross bool) (map[string]bool, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]bool{}
	configured := false
	for owner, byID := range s.rows {
		if !visible(tenant, cross, owner) {
			continue
		}
		for id, r := range byID {
			configured = true
			// A cross-tenant (platform) view sees the union: a framework any
			// visible tenant enabled reads as enabled. Nothing is hidden and
			// nothing is invented; the handler says whose view this is.
			out[id] = out[id] || r.Enabled
		}
	}
	return out, configured, nil
}

func (s *FrameworkFileStore) SetFrameworkStates(_ context.Context, _ string, _ bool, owner string, states []FrameworkState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := s.snapshotLocked()
	for _, st := range states {
		s.putLocked(fileFramework{
			TenantID: owner, FrameworkID: st.FrameworkID, Enabled: st.Enabled,
			UpdatedBy: st.UpdatedBy, UpdatedAt: st.UpdatedAt,
		})
	}
	if err := s.flushLocked(); err != nil {
		// Roll back so the store never reports a selection the file does not hold.
		s.rows = snapshot
		return err
	}
	return nil
}

func (s *FrameworkFileStore) snapshotLocked() map[string]map[string]fileFramework {
	out := make(map[string]map[string]fileFramework, len(s.rows))
	for t, byID := range s.rows {
		inner := make(map[string]fileFramework, len(byID))
		for id, r := range byID {
			inner[id] = r
		}
		out[t] = inner
	}
	return out
}

// ---- Postgres backend (tenant_iso FORCE-RLS via WithTenant, migration 0042) --

type frameworkPGStore struct{ db DB }

// NewFrameworkPGStore builds the Postgres-backed selection register.
func NewFrameworkPGStore(db DB) FrameworkStore { return &frameworkPGStore{db: db} }

func (p *frameworkPGStore) FrameworkStates(ctx context.Context, tenant string, cross bool) (map[string]bool, bool, error) {
	out := map[string]bool{}
	configured := false
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT framework_id, enabled FROM security_framework_state`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				id      string
				enabled bool
			)
			if err := rows.Scan(&id, &enabled); err != nil {
				return err
			}
			configured = true
			out[id] = out[id] || enabled
		}
		return rows.Err()
	})
	if err != nil {
		return nil, false, err
	}
	return out, configured, nil
}

func (p *frameworkPGStore) SetFrameworkStates(ctx context.Context, tenant string, cross bool, owner string, states []FrameworkState) error {
	return p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		for _, st := range states {
			at := st.UpdatedAt
			if at.IsZero() {
				at = time.Now().UTC()
			}
			if _, err := tx.Exec(ctx, `INSERT INTO security_framework_state
			        (tenant_id, framework_id, enabled, updated_by, updated_at)
			    VALUES ($1,$2,$3,$4,$5)
			    ON CONFLICT (tenant_id, framework_id) DO UPDATE
			        SET enabled = EXCLUDED.enabled,
			            updated_by = EXCLUDED.updated_by,
			            updated_at = EXCLUDED.updated_at`,
				NormTenant(owner), st.FrameworkID, st.Enabled, st.UpdatedBy, at); err != nil {
				return err
			}
		}
		return nil
	})
}

var _ FrameworkStore = (*FrameworkFileStore)(nil)
var _ FrameworkStore = (*frameworkPGStore)(nil)
