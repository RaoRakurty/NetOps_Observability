// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

// found_store_pg.go — the Postgres backend of FoundStore (migration
// 0063_discovered_devices.sql). See found_store.go for what is stored and why.
//
// ISOLATION. discovered_devices is FORCE-RLS tenant_iso. Writes run in a
// transaction scoped to each tenant group — WithTenant(tenant, cross=false) —
// so WITH CHECK refuses a row whose tenant_id is not the scope it is written
// under: a stamping bug cannot file a device under another tenant. The boot
// read is the only cross-tenant call (WithTenant("", cross=true)).
//
// BOUNDS (§9). Every call runs under its own 10 s deadline; upserts go in
// chunks of at most foundPGChunk rows per statement, so a full 2×MaxScanHosts
// memory is a handful of statements, never one unbounded one.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// FoundDB is the injected relational seam (the topology.DB idiom).
type FoundDB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

const (
	foundPGTimeout = 10 * time.Second
	foundPGChunk   = 500
)

// PGFoundStore is the Postgres FoundStore.
type PGFoundStore struct{ db FoundDB }

// NewPGFoundStore builds the Postgres backend.
func NewPGFoundStore(db FoundDB) *PGFoundStore { return &PGFoundStore{db: db} }

// Load implements FoundStore.
func (s *PGFoundStore) Load(ctx context.Context, tenant string, cross bool) ([]FoundRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, foundPGTimeout)
	defer cancel()
	var out []FoundRecord
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		out = out[:0]
		// The WHERE is belt-and-braces beside RLS: a scoped read names its
		// tenant even though the policy would already confine it.
		q := `SELECT tenant_id, source, address, device_id, name, vendor, os, credential_ref,
       first_found, last_answered, stale_since, data
  FROM discovered_devices`
		var args []any
		if !cross {
			q += ` WHERE tenant_id = $1`
			args = append(args, normFoundTenant(tenant))
		}
		q += ` ORDER BY tenant_id, source, address`
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r FoundRecord
			var stale *time.Time
			var data []byte
			if err := rows.Scan(&r.TenantID, &r.Source, &r.Address, &r.DeviceID, &r.Name, &r.Vendor, &r.OS,
				&r.CredentialRef, &r.FirstFound, &r.LastAnswered, &stale, &data); err != nil {
				return err
			}
			if stale != nil {
				r.StaleSince = stale.UTC()
			}
			r.FirstFound, r.LastAnswered = r.FirstFound.UTC(), r.LastAnswered.UTC()
			if len(data) > 0 && string(data) != "{}" {
				r.Data = json.RawMessage(data)
			}
			if err := validateFoundRecord(r); err != nil {
				return fmt.Errorf("discovered_devices row %s/%s/%s: %w", r.TenantID, r.Source, r.Address, err)
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("read discovered_devices: %w", err)
	}
	return out, nil
}

// Apply implements FoundStore: one tenant-scoped transaction per tenant group.
func (s *PGFoundStore) Apply(ctx context.Context, upserts []FoundRecord, prunes []FoundKey) error {
	type group struct {
		ups    []FoundRecord
		prunes []FoundKey
	}
	groups := map[string]*group{}
	get := func(t string) *group {
		g := groups[t]
		if g == nil {
			g = &group{}
			groups[t] = g
		}
		return g
	}
	for _, r := range upserts {
		if err := validateFoundRecord(r); err != nil {
			return err
		}
		r.TenantID = normFoundTenant(r.TenantID)
		get(r.TenantID).ups = append(get(r.TenantID).ups, r)
	}
	for _, p := range prunes {
		p.TenantID = normFoundTenant(p.TenantID)
		get(p.TenantID).prunes = append(get(p.TenantID).prunes, p)
	}
	tenants := make([]string, 0, len(groups))
	for t := range groups {
		tenants = append(tenants, t)
	}
	sort.Strings(tenants) // deterministic order: a failure always names the same group
	for _, t := range tenants {
		if err := s.applyTenant(ctx, t, groups[t].ups, groups[t].prunes); err != nil {
			return fmt.Errorf("write discovered_devices (tenant %q): %w", t, err)
		}
	}
	return nil
}

func (s *PGFoundStore) applyTenant(ctx context.Context, tenant string, ups []FoundRecord, prunes []FoundKey) error {
	ctx, cancel := context.WithTimeout(ctx, foundPGTimeout)
	defer cancel()
	return s.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		for start := 0; start < len(ups); start += foundPGChunk {
			end := start + foundPGChunk
			if end > len(ups) {
				end = len(ups)
			}
			if err := upsertFoundChunk(ctx, tx, ups[start:end]); err != nil {
				return err
			}
		}
		for start := 0; start < len(prunes); start += foundPGChunk {
			end := start + foundPGChunk
			if end > len(prunes) {
				end = len(prunes)
			}
			chunk := prunes[start:end]
			srcs := make([]string, len(chunk))
			addrs := make([]string, len(chunk))
			for i, p := range chunk {
				srcs[i], addrs[i] = p.Source, p.Address
			}
			if _, err := tx.Exec(ctx, `DELETE FROM discovered_devices d
 USING unnest($2::text[], $3::text[]) AS p(source, address)
 WHERE d.tenant_id = $1 AND d.source = p.source AND d.address = p.address`, tenant, srcs, addrs); err != nil {
				return err
			}
		}
		return nil
	})
}

func upsertFoundChunk(ctx context.Context, tx pgx.Tx, recs []FoundRecord) error {
	// A chunk must not name the same key twice (ON CONFLICT cannot touch one
	// row twice in a statement); the last write for a key wins, as it would
	// have sequentially.
	idx := map[FoundKey]int{}
	uniq := make([]FoundRecord, 0, len(recs))
	for _, r := range recs {
		if i, ok := idx[r.Key()]; ok {
			uniq[i] = r
			continue
		}
		idx[r.Key()] = len(uniq)
		uniq = append(uniq, r)
	}
	n := len(uniq)
	var (
		tenants, sources, addrs, ids, names, vendors, oses, creds, datas = make([]string, n), make([]string, n),
			make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n),
			make([]string, n), make([]string, n)
		first, answered = make([]time.Time, n), make([]time.Time, n)
		stale           = make([]*time.Time, n)
	)
	for i, r := range uniq {
		tenants[i], sources[i], addrs[i], ids[i] = r.TenantID, r.Source, r.Address, r.DeviceID
		names[i], vendors[i], oses[i], creds[i] = r.Name, r.Vendor, r.OS, r.CredentialRef
		first[i], answered[i] = r.FirstFound.UTC(), r.LastAnswered.UTC()
		if !r.StaleSince.IsZero() {
			t := r.StaleSince.UTC()
			stale[i] = &t
		}
		datas[i] = "{}"
		if len(r.Data) > 0 {
			datas[i] = string(r.Data)
		}
	}
	_, err := tx.Exec(ctx, `
INSERT INTO discovered_devices
   (tenant_id, source, address, device_id, name, vendor, os, credential_ref, first_found, last_answered, stale_since, data)
SELECT u.tenant_id, u.source, u.address, u.device_id, u.name, u.vendor, u.os, u.credential_ref,
       u.first_found, u.last_answered, u.stale_since, u.data::jsonb
  FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[],
              $9::timestamptz[], $10::timestamptz[], $11::timestamptz[], $12::text[])
       AS u(tenant_id, source, address, device_id, name, vendor, os, credential_ref,
            first_found, last_answered, stale_since, data)
ON CONFLICT (tenant_id, source, address) DO UPDATE SET
   device_id=EXCLUDED.device_id, name=EXCLUDED.name, vendor=EXCLUDED.vendor, os=EXCLUDED.os,
   credential_ref=EXCLUDED.credential_ref, first_found=LEAST(discovered_devices.first_found, EXCLUDED.first_found),
   last_answered=EXCLUDED.last_answered, stale_since=EXCLUDED.stale_since, data=EXCLUDED.data`,
		tenants, sources, addrs, ids, names, vendors, oses, creds, first, answered, stale, datas)
	return err
}
