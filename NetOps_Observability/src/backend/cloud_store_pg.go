package main

// cloud_store_pg.go — Postgres backend for the Cloud App Observability inventory
// (WAVE 1 #1, migration 0025). The durable replacement for memCloudStore: one row
// per resource/mapping/connector, tenant-isolated by the tenant_iso FORCE-RLS
// policy. Every method runs through db.withTenant, so RLS is the storage-layer
// backstop (CLAUDE.md §3a.4) even if a handler authz check were bypassed — a scoped
// caller can never read or write another tenant's rows, and QueryResources filters
// + keyset-paginates in SQL (never a whole-inventory load into Go memory).
//
// The canonical filter/sort fields are typed columns; the lossless
// cloud.CloudResource / CloudIdentityMapping is carried in a JSONB `data` column
// (topology_store pattern) and is what a reader reconstructs each record from.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"netops/backend/cloud"
)

type pgCloudStore struct{ db *pgDB }

// ReplaceInventory swaps the whole inventory for ONE tenant (a provider snapshot is
// a full refresh) in a single transaction: delete-then-upsert is atomic, so a
// concurrent reader never sees a half-written inventory. The tenant is stamped from
// the caller (never a row), and withTenant binds the RLS scope to it — the DELETE
// only clears that tenant's rows and the WITH CHECK forbids stamping another's.
func (s *pgCloudStore) ReplaceInventory(ctx context.Context, tenant string, res []cloud.CloudResource, maps []cloud.CloudIdentityMapping) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	t := normTenant(tenant)
	return s.db.withTenant(ctx, tenant, false, func(tx pgx.Tx) error {
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

// ListResources returns the WHOLE tenant inventory (bounded by cloudListHardCap so
// it is never an unbounded SELECT) for the enrichment joins.
func (s *pgCloudStore) ListResources(ctx context.Context, tenant string, cross bool) ([]cloud.CloudResource, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out := make([]cloud.CloudResource, 0)
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT data FROM cloud_resources
		    ORDER BY tenant_id, resource_id LIMIT $1`, cloudListHardCap)
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
func (s *pgCloudStore) QueryResources(ctx context.Context, tenant string, cross bool, f cloudResourceFilter) (cloudResourcePage, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = cloudPageDefault
	}
	where, args := buildCloudWhere(f)
	if f.Cursor != "" {
		curT, curR, ok := decodeCloudCursor(f.Cursor)
		if !ok {
			return cloudResourcePage{}, errBadCursor
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
	page := make([]cloud.CloudResource, 0, limit)
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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
		return cloudResourcePage{}, err
	}
	next := ""
	if len(page) > limit {
		page = page[:limit]
		last := page[len(page)-1]
		next = encodeCloudCursor(last.TenantID, last.ResourceID)
	}
	return cloudResourcePage{Resources: page, NextCursor: next}, nil
}

// GetResource fetches one resource by id within the caller's RLS scope. Another
// tenant's id is invisible under RLS → found=false → 404 upstream (never revealed).
func (s *pgCloudStore) GetResource(ctx context.Context, tenant string, cross bool, resourceID string) (cloud.CloudResource, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out cloud.CloudResource
	found := false
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
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
		return cloud.CloudResource{}, false, err
	}
	return out, found, nil
}

// ListMappings returns the tenant's (match_key → app) attributions (bounded).
func (s *pgCloudStore) ListMappings(ctx context.Context, tenant string, cross bool) ([]cloud.CloudIdentityMapping, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out := make([]cloud.CloudIdentityMapping, 0)
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT data FROM cloud_identity_mappings
		    ORDER BY tenant_id, match_key_type, match_key LIMIT $1`, cloudListHardCap)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var data []byte
			if err := rows.Scan(&data); err != nil {
				return err
			}
			var m cloud.CloudIdentityMapping
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
func (s *pgCloudStore) ReplaceConnectors(ctx context.Context, tenant string, conns []cloud.ConnectorInfo) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	t := normTenant(tenant)
	return s.db.withTenant(ctx, tenant, false, func(tx pgx.Tx) error {
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
func (s *pgCloudStore) ListConnectors(ctx context.Context, tenant string, cross bool) ([]cloud.ConnectorInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := make([]cloud.ConnectorInfo, 0)
	err := s.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT provider, account_id, kind, collected_at, resource_count
		    FROM cloud_inventory_connectors ORDER BY tenant_id, provider, account_id LIMIT $1`, cloudListHardCap)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c cloud.ConnectorInfo
			var provider string
			var collected *time.Time
			if err := rows.Scan(&provider, &c.AccountID, &c.Kind, &collected, &c.ResourceCount); err != nil {
				return err
			}
			c.Provider = cloud.Provider(provider)
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
// their args (cursor/limit are appended by the caller). Mirrors matchCloudResource.
func buildCloudWhere(f cloudResourceFilter) ([]string, []any) {
	var where []string
	var args []any
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if f.Provider != "" {
		add("lower(cloud_provider) = lower($%d)", f.Provider)
	}
	if f.Account != "" {
		add("account_id = $%d", f.Account)
	}
	if f.Region != "" {
		add("region = $%d", f.Region)
	}
	if f.Type != "" {
		add("resource_type = $%d", f.Type)
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

func scanCloudResource(rows pgx.Rows) (cloud.CloudResource, error) {
	var data []byte
	if err := rows.Scan(&data); err != nil {
		return cloud.CloudResource{}, err
	}
	var r cloud.CloudResource
	if err := json.Unmarshal(data, &r); err != nil {
		return cloud.CloudResource{}, err
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

var _ cloudStore = (*pgCloudStore)(nil)
