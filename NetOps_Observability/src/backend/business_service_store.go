package main

// business_service_store.go — persistent, tenant-isolated storage for the
// Business Service mapping (Azure optional-tags epic, migration 0024).
//
// Two surfaces:
//   business_services  — the named BusinessService registry (create/list/rename/delete).
//   resource_mappings  — resource_id → service, the manual override/confirm layer
//                        a human sets on top of the automatic inference. A manual
//                        override wins over inference and is treated as confirmed.
//
// Every method runs through db.withTenant, so the FORCE-RLS tenant_iso policy is
// the storage-layer backstop (CLAUDE.md §3a.4) even if a handler authz check were
// ever bypassed. Postgres-backed only (nil on the file backend, like the service
// catalog store) — the handler returns 501 when nil.

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// BusinessService is a named, tenant-owned service in the registry.
type BusinessService struct {
	BusinessServiceID string    `json:"business_service_id"`
	TenantID          string    `json:"tenant_id"`
	Name              string    `json:"name"`
	Description       string    `json:"description"`
	Criticality       string    `json:"criticality"`
	Owner             string    `json:"owner"`
	RunbookURL        string    `json:"runbook_url"`
	CreatedBy         string    `json:"created_by"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// ResourceMapping is one resource_id → service binding (the override layer).
type ResourceMapping struct {
	TenantID          string    `json:"tenant_id"`
	ResourceID        string    `json:"resource_id"`
	BusinessServiceID string    `json:"business_service_id,omitempty"`
	ServiceName       string    `json:"service_name"`
	Source            string    `json:"source"`     // inferred | manual
	Confidence        string    `json:"confidence"` // confirmed | strong | suspected | weak
	Basis             string    `json:"basis"`
	IsManualOverride  bool      `json:"is_manual_override"`
	CreatedBy         string    `json:"created_by"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// errConflict is returned when a create/rename collides with the per-tenant
// unique service name (mapped to HTTP 409 by the handler).
var errConflict = errors.New("already exists")

type pgBusinessServiceStore struct{ db *pgDB }

func newBusinessServiceStore() *pgBusinessServiceStore {
	if ps, ok := backend.(*pgStore); ok {
		return &pgBusinessServiceStore{db: ps.db}
	}
	return nil // Postgres backend only
}

// ListServices returns the tenant's named services (newest first).
func (st *pgBusinessServiceStore) ListServices(ctx context.Context, tenant string, cross bool) ([]BusinessService, error) {
	out := make([]BusinessService, 0)
	err := st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT business_service_id, tenant_id, name, description,
		        criticality, owner, runbook_url, created_by, created_at, updated_at
		    FROM business_services ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b BusinessService
			if err := rows.Scan(&b.BusinessServiceID, &b.TenantID, &b.Name, &b.Description,
				&b.Criticality, &b.Owner, &b.RunbookURL, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt); err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

// CreateService inserts a named service. The tenant is stamped from the caller's
// principal, never a request body. Returns errConflict on a duplicate name.
func (st *pgBusinessServiceStore) CreateService(ctx context.Context, tenant string, cross bool, in BusinessService) (BusinessService, error) {
	id, err := newUUIDv4()
	if err != nil {
		return BusinessService{}, err
	}
	in.BusinessServiceID = id
	if in.Criticality == "" {
		in.Criticality = "normal"
	}
	err = st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `INSERT INTO business_services
		        (business_service_id, tenant_id, name, description, criticality, owner, runbook_url, created_by)
		    VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at, updated_at`,
			in.BusinessServiceID, in.TenantID, in.Name, in.Description, in.Criticality, in.Owner, in.RunbookURL, in.CreatedBy)
		return row.Scan(&in.CreatedAt, &in.UpdatedAt)
	})
	if isUniqueViolation(err) {
		return BusinessService{}, errConflict
	}
	return in, err
}

// RenameService edits a service's name/description/criticality. Returns false if
// no visible row matched (cross-tenant id → 404 upstream). errConflict on a name clash.
func (st *pgBusinessServiceStore) UpdateService(ctx context.Context, tenant string, cross bool, id string, in BusinessService) (bool, error) {
	affected := false
	err := st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		crit := in.Criticality
		if crit == "" {
			crit = "normal"
		}
		ct, e := tx.Exec(ctx, `UPDATE business_services
		    SET name = $2, description = $3, criticality = $4, owner = $5, runbook_url = $6, updated_at = now()
		    WHERE business_service_id = $1`, id, in.Name, in.Description, crit, in.Owner, in.RunbookURL)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected() > 0
		return nil
	})
	if isUniqueViolation(err) {
		return false, errConflict
	}
	return affected, err
}

// DeleteService removes a named service AND clears any mappings that referenced
// it (the resources revert to inference). Returns false if not found/visible.
func (st *pgBusinessServiceStore) DeleteService(ctx context.Context, tenant string, cross bool, id string) (bool, error) {
	affected := false
	err := st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		// Unbind mappings first (same tenant scope; RLS keeps it in-tenant).
		if _, e := tx.Exec(ctx, `DELETE FROM resource_mappings WHERE business_service_id = $1`, id); e != nil {
			return e
		}
		ct, e := tx.Exec(ctx, `DELETE FROM business_services WHERE business_service_id = $1`, id)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected() > 0
		return nil
	})
	return affected, err
}

// ListMappings returns the tenant's resource→service mappings.
func (st *pgBusinessServiceStore) ListMappings(ctx context.Context, tenant string, cross bool) ([]ResourceMapping, error) {
	out := make([]ResourceMapping, 0)
	err := st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id, resource_id,
		        coalesce(business_service_id::text,''), service_name, source, confidence,
		        basis, is_manual_override, created_by, created_at, updated_at
		    FROM resource_mappings ORDER BY updated_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m ResourceMapping
			if err := rows.Scan(&m.TenantID, &m.ResourceID, &m.BusinessServiceID, &m.ServiceName,
				&m.Source, &m.Confidence, &m.Basis, &m.IsManualOverride, &m.CreatedBy,
				&m.CreatedAt, &m.UpdatedAt); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// AssignResources upserts a manual mapping for each resource_id to the named
// service (bulk assignment). If serviceID is non-empty it binds to that named
// service; the service_name is denormalized either way for display/attribution.
// A manual assignment is authoritative (is_manual_override=true, confirmed).
// Returns the number of resources mapped.
func (st *pgBusinessServiceStore) AssignResources(ctx context.Context, tenant string, cross bool, serviceID, serviceName, createdBy string, resourceIDs []string) (int, error) {
	n := 0
	err := st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		// If a named service id was given, it must exist + be visible under RLS.
		var svcArg any
		if serviceID != "" {
			var exists bool
			if e := tx.QueryRow(ctx, `SELECT true FROM business_services WHERE business_service_id = $1`, serviceID).Scan(&exists); e != nil {
				if errors.Is(e, pgx.ErrNoRows) {
					return errNotFound
				}
				return e
			}
			svcArg = serviceID
		}
		for _, rid := range resourceIDs {
			rid = strings.TrimSpace(rid)
			if rid == "" {
				continue
			}
			ct, e := tx.Exec(ctx, `INSERT INTO resource_mappings
			        (tenant_id, resource_id, business_service_id, service_name, source,
			         confidence, basis, is_manual_override, created_by)
			    VALUES (current_setting('app.tenant_id', true), $1, $2, $3, 'manual',
			            'confirmed', 'operator assignment', true, $4)
			    ON CONFLICT (tenant_id, resource_id) DO UPDATE
			    SET business_service_id = EXCLUDED.business_service_id,
			        service_name = EXCLUDED.service_name, source = 'manual',
			        confidence = 'confirmed', basis = 'operator assignment',
			        is_manual_override = true, created_by = EXCLUDED.created_by,
			        updated_at = now()`, rid, svcArg, serviceName, createdBy)
			if e != nil {
				return e
			}
			n += int(ct.RowsAffected())
		}
		return nil
	})
	return n, err
}

// ClearMapping removes a resource's manual override (it reverts to inference).
// Returns false when no visible row matched.
func (st *pgBusinessServiceStore) ClearMapping(ctx context.Context, tenant string, cross bool, resourceID string) (bool, error) {
	affected := false
	err := st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `DELETE FROM resource_mappings WHERE resource_id = $1`, resourceID)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected() > 0
		return nil
	})
	return affected, err
}

// mappingsByResource returns the tenant's manual mappings keyed by resource_id —
// the overlay handleCloudResources applies so a confirmed override wins over the
// inventory's inferred attribution.
func (st *pgBusinessServiceStore) mappingsByResource(ctx context.Context, tenant string, cross bool) (map[string]ResourceMapping, error) {
	list, err := st.ListMappings(ctx, tenant, cross)
	if err != nil {
		return nil, err
	}
	out := make(map[string]ResourceMapping, len(list))
	for _, m := range list {
		out[m.ResourceID] = m
	}
	return out, nil
}
