// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package servicecat is the Service catalog domain (#69 §2, P2) — the semantic
// lens over the truth streams. Postgres-backed (lifecycle/catalog state, RLS
// tenant-isolated), nil on the file backend like incidents/seams. Three split
// objects: services (stable identity), service_selectors (versioned,
// append-only grouping rule), service_bindings (operational attachments).
// The HTTP surface and the backend selector stay in package main.
package servicecat

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/platformdb"
)

// ErrNotFound is returned when a service (or binding) is absent — or invisible
// under the caller's RLS scope, which must render identically (honest 404).
var ErrNotFound = errors.New("not found")

// ValidCriticality allowlists the service-criticality vocabulary (shared with
// the cloud business-service handlers).
var ValidCriticality = map[string]bool{"critical": true, "high": true, "normal": true, "low": true}

// ValidBindingKind allowlists the operational attachment kinds.
var ValidBindingKind = map[string]bool{"probe": true, "path": true, "seam": true}

// Service — stable identity. Renames don't break attribution history; archive,
// never hard-delete.
type Service struct {
	ServiceID   string     `json:"service_id"`
	TenantID    string     `json:"tenant_id"`
	Name        string     `json:"name"`
	Criticality string     `json:"criticality"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
	ArchivedAt  *time.Time `json:"archived_at,omitempty"`
}

// ServiceSelector — the versioned grouping rule. Spec carries the predicates
// (dst_prefixes/ports/protocols/remote_asns/domains/tags).
type ServiceSelector struct {
	ServiceID     string         `json:"service_id"`
	Version       int            `json:"version"`
	EffectiveFrom time.Time      `json:"effective_from"`
	Spec          map[string]any `json:"spec"`
	CreatedBy     string         `json:"created_by"`
	CreatedAt     time.Time      `json:"created_at"`
}

// ServiceBinding — what we operate for the service (probe/path/seam).
type ServiceBinding struct {
	BindingID string    `json:"binding_id"`
	ServiceID string    `json:"service_id"`
	Kind      string    `json:"kind"`
	Ref       string    `json:"ref"`
	CreatedAt time.Time `json:"created_at"`
}

// SelectorSet is one (tenant, service, latest-selector) attribution unit the
// rollup worker materializes. Tenant comes from the SERVICE ROW (never a request),
// so a rollup row can only ever be stamped with its owner's tenant.
type SelectorSet struct {
	TenantID  string
	ServiceID string
	Version   int
	Spec      map[string]any
}

// newUUIDv4 generates a random UUID (stdlib crypto/rand; no dependency).
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ValidateInput is a pure guard (unit-tested) for create/update.
func ValidateInput(name, criticality string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("service name is required")
	}
	if len(name) > 120 {
		return errors.New("service name too long (max 120)")
	}
	if criticality != "" && !ValidCriticality[criticality] {
		return errors.New("criticality must be one of critical|high|normal|low")
	}
	return nil
}

// Store is the Postgres service-catalog repository. Every query runs inside
// WithTenant, so the FORCE-RLS policies scope reads and writes to the caller.
type Store struct{ db *platformdb.DB }

// NewStore wraps the platform DB pool. The backend selection (Postgres-only,
// nil on the file backend) stays with the caller.
func NewStore(db *platformdb.DB) *Store { return &Store{db: db} }

func (st *Store) ListServices(ctx context.Context, tenant string, cross bool, includeArchived bool) ([]Service, error) {
	out := make([]Service, 0)
	q := `SELECT service_id, tenant_id, name, criticality, description, created_at, archived_at
            FROM services`
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
			var s Service
			if err := rows.Scan(&s.ServiceID, &s.TenantID, &s.Name, &s.Criticality, &s.Description, &s.CreatedAt, &s.ArchivedAt); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

func (st *Store) GetService(ctx context.Context, tenant string, cross bool, id string) (Service, bool, error) {
	var s Service
	found := false
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT service_id, tenant_id, name, criticality, description, created_at, archived_at
              FROM services WHERE service_id = $1`, id)
		e := row.Scan(&s.ServiceID, &s.TenantID, &s.Name, &s.Criticality, &s.Description, &s.CreatedAt, &s.ArchivedAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		found = true
		return nil
	})
	return s, found, err
}

func (st *Store) CreateService(ctx context.Context, tenant string, cross bool, in Service) (Service, error) {
	id, err := newUUIDv4()
	if err != nil {
		return Service{}, err
	}
	in.ServiceID = id
	if in.Criticality == "" {
		in.Criticality = "normal"
	}
	err = st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `INSERT INTO services (service_id, tenant_id, name, criticality, description)
              VALUES ($1,$2,$3,$4,$5) RETURNING created_at`, in.ServiceID, in.TenantID, in.Name, in.Criticality, in.Description)
		return row.Scan(&in.CreatedAt)
	})
	return in, err
}

// ArchiveService soft-deletes (sets archived_at) — never a hard DELETE, because
// flow attribution history references the service_id. Returns false if not found.
func (st *Store) ArchiveService(ctx context.Context, tenant string, cross bool, id string) (bool, error) {
	affected := false
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `UPDATE services SET archived_at = now() WHERE service_id = $1 AND archived_at IS NULL`, id)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected() > 0
		return nil
	})
	return affected, err
}

func (st *Store) ListSelectors(ctx context.Context, tenant string, cross bool, serviceID string) ([]ServiceSelector, error) {
	out := make([]ServiceSelector, 0)
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT service_id, version, effective_from, spec, created_by, created_at
              FROM service_selectors WHERE service_id = $1 ORDER BY version DESC`, serviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sel ServiceSelector
			var spec []byte
			if err := rows.Scan(&sel.ServiceID, &sel.Version, &sel.EffectiveFrom, &spec, &sel.CreatedBy, &sel.CreatedAt); err != nil {
				return err
			}
			if err := json.Unmarshal(spec, &sel.Spec); err != nil {
				return fmt.Errorf("selector %s v%d spec: %w", sel.ServiceID, sel.Version, err)
			}
			out = append(out, sel)
		}
		return rows.Err()
	})
	return out, err
}

// AddSelector appends a NEW version (max+1) — selectors are append-only so past
// attribution stays reproducible. effective_from defaults to now.
func (st *Store) AddSelector(ctx context.Context, tenant string, cross bool, serviceID string, spec map[string]any, createdBy string) (ServiceSelector, error) {
	if spec == nil {
		spec = map[string]any{}
	}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return ServiceSelector{}, err
	}
	sel := ServiceSelector{ServiceID: serviceID, Spec: spec, CreatedBy: createdBy}
	err = st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		// service must exist + be visible under RLS (FK-by-policy + honest 404 upstream)
		var exists bool
		if e := tx.QueryRow(ctx, `SELECT true FROM services WHERE service_id = $1`, serviceID).Scan(&exists); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return e
		}
		row := tx.QueryRow(ctx, `INSERT INTO service_selectors (tenant_id, service_id, version, spec, created_by)
              VALUES (current_setting('app.tenant_id', true), $1,
                      (SELECT coalesce(max(version),0)+1 FROM service_selectors WHERE service_id = $1), $2, $3)
              RETURNING version, effective_from, created_at`, serviceID, specJSON, createdBy)
		return row.Scan(&sel.Version, &sel.EffectiveFrom, &sel.CreatedAt)
	})
	return sel, err
}

// ActiveSelectorSets returns, across ALL tenants (cross-tenant read — background
// worker only, never exposed over HTTP), the latest selector version of every
// non-archived service that has at least one selector. Bounded by `limit`
// (oldest services first, so attribution is stable as the catalog grows).
func (st *Store) ActiveSelectorSets(ctx context.Context, limit int) ([]SelectorSet, error) {
	if limit <= 0 {
		limit = 200
	}
	out := make([]SelectorSet, 0)
	err := st.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT s.tenant_id, s.service_id, sel.version, sel.spec
              FROM services s
              JOIN LATERAL (SELECT version, spec FROM service_selectors ss
                             WHERE ss.tenant_id = s.tenant_id AND ss.service_id = s.service_id
                             ORDER BY version DESC LIMIT 1) sel ON true
             WHERE s.archived_at IS NULL
             ORDER BY s.created_at ASC
             LIMIT $1`, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var set SelectorSet
			var spec []byte
			if err := rows.Scan(&set.TenantID, &set.ServiceID, &set.Version, &spec); err != nil {
				return err
			}
			if err := json.Unmarshal(spec, &set.Spec); err != nil {
				return fmt.Errorf("selector %s v%d spec: %w", set.ServiceID, set.Version, err)
			}
			out = append(out, set)
		}
		return rows.Err()
	})
	return out, err
}

func (st *Store) ListBindings(ctx context.Context, tenant string, cross bool, serviceID string) ([]ServiceBinding, error) {
	out := make([]ServiceBinding, 0)
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT binding_id, service_id, kind, ref, created_at
              FROM service_bindings WHERE service_id = $1 ORDER BY created_at`, serviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b ServiceBinding
			if err := rows.Scan(&b.BindingID, &b.ServiceID, &b.Kind, &b.Ref, &b.CreatedAt); err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

func (st *Store) AddBinding(ctx context.Context, tenant string, cross bool, serviceID, kind, ref string) (ServiceBinding, error) {
	id, err := newUUIDv4()
	if err != nil {
		return ServiceBinding{}, err
	}
	b := ServiceBinding{BindingID: id, ServiceID: serviceID, Kind: kind, Ref: ref}
	err = st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		var exists bool
		if e := tx.QueryRow(ctx, `SELECT true FROM services WHERE service_id = $1`, serviceID).Scan(&exists); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return e
		}
		row := tx.QueryRow(ctx, `INSERT INTO service_bindings (binding_id, tenant_id, service_id, kind, ref)
              VALUES ($1, current_setting('app.tenant_id', true), $2, $3, $4) RETURNING created_at`,
			id, serviceID, kind, ref)
		return row.Scan(&b.CreatedAt)
	})
	return b, err
}

func (st *Store) DeleteBinding(ctx context.Context, tenant string, cross bool, serviceID, bindingID string) (bool, error) {
	affected := false
	err := st.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `DELETE FROM service_bindings WHERE binding_id = $1 AND service_id = $2`, bindingID, serviceID)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected() > 0
		return nil
	})
	return affected, err
}
