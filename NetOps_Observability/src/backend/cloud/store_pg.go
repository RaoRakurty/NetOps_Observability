// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloud

// cloud_store_pg.go — Postgres backend for the Cloud App Observability inventory
// (WAVE 1 #1, migration 0025). The durable replacement for memStore: one row
// per resource/mapping/connector, tenant-isolated by the tenant_iso FORCE-RLS
// policy. Every method runs through db.withTenant, so RLS is the storage-layer
// backstop (CLAUDE.md §3a.4) even if a handler authz check were bypassed — a scoped
// caller can never read or write another tenant's rows, and QueryResources filters
// + keyset-paginates in SQL (never a whole-inventory load into Go memory).
//
// The canonical filter/sort fields are typed columns; the lossless
// CloudResource / CloudIdentityMapping is carried in a JSONB `data` column
// (topology_store pattern) and is what a reader reconstructs each record from.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// DB is the injected relational seam (the portintel.DB idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type PGStore struct{ db DB }

// NewPGStore builds the FORCE-RLS pg repository over the injected seam.
func NewPGStore(db DB) *PGStore { return &PGStore{db: db} }

// orUnknown mirrors the integrator's display default (duplicated per the
// no-shared-utils rule).
func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}

// ReplaceInventory swaps the whole inventory for ONE tenant (a provider snapshot is
// a full refresh) in a single transaction: delete-then-upsert is atomic, so a
// concurrent reader never sees a half-written inventory. The tenant is stamped from
// the caller (never a row), and withTenant binds the RLS scope to it — the DELETE
// only clears that tenant's rows and the WITH CHECK forbids stamping another's.
func (s *PGStore) ReplaceInventory(ctx context.Context, tenant string, res []CloudResource, maps []CloudIdentityMapping) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	t := normTenant(tenant)
	return s.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM cloud_resources`); err != nil {
			return err
		}
		for i := range res {
			r := res[i]
			r.TenantID = t
			data, err := json.Marshal(r)
			if err != nil {
				return err
			}
			tags := tagsJSON(r.Tags)
			if _, err := tx.Exec(ctx, `INSERT INTO cloud_resources
			        (tenant_id, resource_id, cloud_provider, account_id, region, resource_type,
			         app_id, confidence, source, discovered_at, last_seen_at, tags, data)
			    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			    ON CONFLICT (tenant_id, resource_id) DO UPDATE SET
			        cloud_provider=EXCLUDED.cloud_provider, account_id=EXCLUDED.account_id,
			        region=EXCLUDED.region, resource_type=EXCLUDED.resource_type,
			        app_id=EXCLUDED.app_id, confidence=EXCLUDED.confidence, source=EXCLUDED.source,
			        discovered_at=EXCLUDED.discovered_at, last_seen_at=EXCLUDED.last_seen_at,
			        tags=EXCLUDED.tags, data=EXCLUDED.data`,
				t, r.ResourceID, string(r.Provider), r.AccountID, r.Region, r.ResourceType,
				r.AppID, orUnknown(string(r.Confidence)), orUnknown(string(r.Source)),
				r.DiscoveredAt, r.LastSeenAt, tags, data); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM cloud_identity_mappings`); err != nil {
			return err
		}
		for i := range maps {
			mp := maps[i]
			mp.TenantID = t
			data, err := json.Marshal(mp)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO cloud_identity_mappings
			        (tenant_id, match_key_type, match_key, app_id, data)
			    VALUES ($1,$2,$3,$4,$5)
			    ON CONFLICT (tenant_id, match_key_type, match_key) DO UPDATE SET
			        app_id=EXCLUDED.app_id, data=EXCLUDED.data`,
				t, string(mp.MatchKeyType), mp.MatchKey, mp.AppID, data); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListResources returns the WHOLE tenant inventory (bounded by ListHardCap so
// it is never an unbounded SELECT) for the enrichment joins.
func (s *PGStore) ListResources(ctx context.Context, tenant string, cross bool) ([]CloudResource, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out := make([]CloudResource, 0)
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT data FROM cloud_resources
		    ORDER BY tenant_id, resource_id LIMIT $1`, ListHardCap)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanCloudResource(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// QueryResources filters + keyset-paginates IN SQL. The WHERE clause is built from
// the set filter fields (all parameterized — no string interpolation of caller
// input), the keyset predicate resumes after the opaque cursor, and LIMIT is
// page+1 so we detect whether a next page exists without a second COUNT query.
func (s *PGStore) QueryResources(ctx context.Context, tenant string, cross bool, f ResourceFilter) (ResourcePage, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = PageDefault
	}
	where, args := buildCloudWhere(f)
	if f.Cursor != "" {
		curT, curR, ok := DecodeCursor(f.Cursor)
		if !ok {
			return ResourcePage{}, ErrBadCursor
		}
		args = append(args, curT, curR)
		where = append(where, fmt.Sprintf("(tenant_id, resource_id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	q := "SELECT data FROM cloud_resources"
	for i, c := range where {
		if i == 0 {
			q += " WHERE " + c
		} else {
			q += " AND " + c
		}
	}
	args = append(args, limit+1)
	q += fmt.Sprintf(" ORDER BY tenant_id, resource_id LIMIT $%d", len(args))

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	page := make([]CloudResource, 0, limit)
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanCloudResource(rows)
			if err != nil {
				return err
			}
			page = append(page, r)
		}
		return rows.Err()
	})
	if err != nil {
		return ResourcePage{}, err
	}
	next := ""
	if len(page) > limit {
		page = page[:limit]
		last := page[len(page)-1]
		next = EncodeCursor(last.TenantID, last.ResourceID)
	}
	return ResourcePage{Resources: page, NextCursor: next}, nil
}

// GetResource fetches one resource by id within the caller's RLS scope. Another
// tenant's id is invisible under RLS → found=false → 404 upstream (never revealed).
func (s *PGStore) GetResource(ctx context.Context, tenant string, cross bool, resourceID string) (CloudResource, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out CloudResource
	found := false
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		var data []byte
		err := tx.QueryRow(ctx, `SELECT data FROM cloud_resources WHERE resource_id = $1 LIMIT 1`, resourceID).Scan(&data)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return CloudResource{}, false, err
	}
	return out, found, nil
}

// ListMappings returns the tenant's (match_key → app) attributions (bounded).
func (s *PGStore) ListMappings(ctx context.Context, tenant string, cross bool) ([]CloudIdentityMapping, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out := make([]CloudIdentityMapping, 0)
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT data FROM cloud_identity_mappings
		    ORDER BY tenant_id, match_key_type, match_key LIMIT $1`, ListHardCap)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var data []byte
			if err := rows.Scan(&data); err != nil {
				return err
			}
			var m CloudIdentityMapping
			if err := json.Unmarshal(data, &m); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// ReplaceConnectors swaps the inventory-source provenance for ONE tenant (same
// full-refresh contract as ReplaceInventory).
func (s *PGStore) ReplaceConnectors(ctx context.Context, tenant string, conns []ConnectorInfo) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	t := normTenant(tenant)
	return s.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM cloud_inventory_connectors`); err != nil {
			return err
		}
		for _, c := range conns {
			var collected any
			if !c.CollectedAt.IsZero() {
				collected = c.CollectedAt
			}
			if _, err := tx.Exec(ctx, `INSERT INTO cloud_inventory_connectors
			        (tenant_id, provider, account_id, kind, collected_at, resource_count)
			    VALUES ($1,$2,$3,$4,$5,$6)
			    ON CONFLICT (tenant_id, provider, account_id) DO UPDATE SET
			        kind=EXCLUDED.kind, collected_at=EXCLUDED.collected_at,
			        resource_count=EXCLUDED.resource_count`,
				t, string(c.Provider), c.AccountID, c.Kind, collected, c.ResourceCount); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListConnectors returns the tenant's inventory-source provenance.
func (s *PGStore) ListConnectors(ctx context.Context, tenant string, cross bool) ([]ConnectorInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := make([]ConnectorInfo, 0)
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT provider, account_id, kind, collected_at, resource_count
		    FROM cloud_inventory_connectors ORDER BY tenant_id, provider, account_id LIMIT $1`, ListHardCap)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c ConnectorInfo
			var provider string
			var collected *time.Time
			if err := rows.Scan(&provider, &c.AccountID, &c.Kind, &collected, &c.ResourceCount); err != nil {
				return err
			}
			c.Provider = Provider(provider)
			if collected != nil {
				c.CollectedAt = *collected
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// buildCloudWhere turns the set filter fields into parameterized WHERE clauses +
// their args (cursor/limit are appended by the caller). Mirrors matchResource.
func buildCloudWhere(f ResourceFilter) ([]string, []any) {
	var where []string
	var args []any
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	// Provider/Account/Region are multi-value (comma-separated OR sets, Wave 2 #5
	// scope bar); pgx v5 binds []string as text[], so `= ANY($n)` stays fully
	// parameterized — a value never reaches the SQL text.
	if vals := FilterValues(f.Provider); len(vals) > 0 {
		for i := range vals {
			vals[i] = strings.ToLower(vals[i])
		}
		add("lower(cloud_provider) = ANY($%d)", vals)
	}
	if vals := FilterValues(f.Account); len(vals) > 0 {
		add("account_id = ANY($%d)", vals)
	}
	if vals := FilterValues(f.Region); len(vals) > 0 {
		add("region = ANY($%d)", vals)
	}
	if f.Type != "" {
		add("resource_type = $%d", f.Type)
	}
	// Family / resource CLASS (Wave 5 #15): expressed over the SAME kinds.go
	// vocabulary matchResource uses. A named family is its (lowercased)
	// type set; "other" is the complement of every known type.
	if f.Family != "" {
		if f.Family == FamilyOther {
			args = append(args, KnownComponentTypes())
			where = append(where, fmt.Sprintf("NOT (lower(resource_type) = ANY($%d))", len(args)))
		} else {
			add("lower(resource_type) = ANY($%d)", FamilyTypes(f.Family))
		}
	}
	switch f.Attribution {
	case "":
		// no filter
	case "attributed":
		where = append(where, "confidence <> 'unknown'")
	case "unattributed":
		where = append(where, "confidence = 'unknown'")
	default:
		add("confidence = $%d", f.Attribution)
	}
	if f.Tag != "" {
		key, val, hasVal := strings.Cut(f.Tag, "=")
		if hasVal {
			args = append(args, key, val)
			where = append(where, fmt.Sprintf("tags ->> $%d = $%d", len(args)-1, len(args)))
		} else {
			add("jsonb_exists(tags, $%d)", key)
		}
	}
	return where, args
}

func scanCloudResource(rows pgx.Rows) (CloudResource, error) {
	var data []byte
	if err := rows.Scan(&data); err != nil {
		return CloudResource{}, err
	}
	var r CloudResource
	if err := json.Unmarshal(data, &r); err != nil {
		return CloudResource{}, err
	}
	return r, nil
}

// tagsJSON marshals a tag map to jsonb text, defaulting nil to an empty object so
// the GIN index / jsonb_exists never operate on a JSON null.
func tagsJSON(tags map[string]string) []byte {
	if len(tags) == 0 {
		return []byte("{}")
	}
	b, err := json.Marshal(tags)
	if err != nil {
		return []byte("{}")
	}
	return b
}

var _ Store = (*PGStore)(nil)
