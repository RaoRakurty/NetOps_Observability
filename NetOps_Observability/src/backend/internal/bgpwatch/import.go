package bgpwatch

// import.go — the one-time file→Postgres cutover for the BGP watchlist and the
// per-tenant alert policy (tracker 245 / the 2026-09-06 importer extension).
//
// Both registers are selected by STORE_BACKEND. A cutover that lost them stops
// the evaluator watching ANY prefix — silently, because an empty watchlist and
// a watchlist that never loaded render identically as "nothing is being
// watched". That is the exact failure the file store's LoadErr exists to make
// visible at runtime, and it must not be reintroduced by a migration.
//
// The watchlist rows are written here rather than through the root package's
// Add(): the table is this domain's, the file shape is this package's, and the
// import must preserve created_at, which Add() defaults to now().

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// importTimeout bounds a whole-collection write (§9).
const importTimeout = 2 * time.Minute

// CountWatchlistRows reports how many watchlist rows the Postgres target holds
// across every tenant (platform scope — the importer's own read).
func CountWatchlistRows(ctx context.Context, db DB) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var n int
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM bgp_watchlist`).Scan(&n)
	})
	return n, err
}

// ImportWatchlistFile writes the file watchlist into bgp_watchlist, preserving
// each row's owning tenant, note, author and created_at. Returns the number of
// rows written.
//
// Stricter than NewWatchFileStore, which drops an unsanitizable row so a
// running install keeps serving: a migration refuses instead, because a dropped
// prefix is a prefix nobody is watching and nobody was told about.
func ImportWatchlistFile(ctx context.Context, db DB, raw []byte) (int, error) {
	var buckets map[string][]WatchEntry
	if err := json.Unmarshal(raw, &buckets); err != nil {
		return 0, fmt.Errorf("bgpwatch: the watchlist file is malformed: %w", err)
	}
	type row struct {
		tenant string
		entry  WatchEntry
	}
	rows := []row{}
	for rawTenant, list := range buckets {
		tenant, err := concreteTenant(rawTenant)
		if err != nil {
			return 0, fmt.Errorf("bgpwatch: the watchlist file holds a non-concrete tenant bucket %q", rawTenant)
		}
		if len(list) > MaxWatchEntriesPerTenant {
			return 0, fmt.Errorf("bgpwatch: tenant %s watches %d resources, over the %d cap — refusing to import a truncated watchlist",
				tenant, len(list), MaxWatchEntriesPerTenant)
		}
		for _, e := range list {
			clean, ok := sanitizeWatchEntry(e)
			if !ok {
				return 0, fmt.Errorf("bgpwatch: tenant %s holds an invalid watchlist row %q", tenant, e.Resource)
			}
			rows = append(rows, row{tenant: tenant, entry: clean})
		}
	}
	if len(rows) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, r := range rows {
			created := r.entry.CreatedAt
			if created.IsZero() {
				created = time.Now().UTC()
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO bgp_watchlist (tenant_id, resource, kind, note, added_by, created_at)
				 VALUES ($1,$2,$3,$4,$5,$6)`,
				r.tenant, r.entry.Resource, r.entry.Kind, r.entry.Note, r.entry.AddedBy, created.UTC()); err != nil {
				return fmt.Errorf("bgpwatch: import watch %s (tenant %s): %w", r.entry.Resource, r.tenant, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

// CountPolicyRows reports how many per-tenant alert-policy rows the Postgres
// target holds (platform scope — the importer's own read).
func CountPolicyRows(ctx context.Context, db DB) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var n int
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM bgp_alert_policy`).Scan(&n)
	})
	return n, err
}

// ImportPolicyFile writes the file policy register into bgp_alert_policy, one
// row per tenant, preserving the author and the update stamp. Returns the
// number of rows written.
//
// Every policy is re-Normalized before it is stored: the JSONB column is opaque
// to the database, so the boundary's own validator is the only thing that keeps
// an unparseable prefix or an out-of-range threshold out of it (§3 — stored
// input is still untrusted input).
func ImportPolicyFile(ctx context.Context, db DB, raw []byte) (int, error) {
	var buckets map[string]TenantPolicy
	if err := json.Unmarshal(raw, &buckets); err != nil {
		return 0, fmt.Errorf("bgpwatch: the alert-policy file is malformed: %w", err)
	}
	type row struct {
		tenant string
		body   []byte
		by     string
		at     time.Time
	}
	rows := []row{}
	for rawTenant, p := range buckets {
		tenant, err := concreteTenant(rawTenant)
		if err != nil {
			return 0, fmt.Errorf("bgpwatch: the alert-policy file holds a non-concrete tenant bucket %q", rawTenant)
		}
		norm, err := p.Normalize()
		if err != nil {
			return 0, fmt.Errorf("bgpwatch: tenant %s holds an invalid alert policy: %w", tenant, err)
		}
		body, err := json.Marshal(TenantPolicy{Default: norm.Default, Prefixes: norm.Prefixes})
		if err != nil {
			return 0, err
		}
		if len(body) > MaxPolicyBytes {
			return 0, fmt.Errorf("bgpwatch: tenant %s alert policy exceeds the %d-byte bound", tenant, MaxPolicyBytes)
		}
		at := p.UpdatedAt
		if at.IsZero() {
			at = time.Now().UTC()
		}
		rows = append(rows, row{tenant: tenant, body: body, by: clip(p.UpdatedBy, 128), at: at.UTC()})
	}
	if len(rows) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, r := range rows {
			if _, err := tx.Exec(ctx,
				`INSERT INTO bgp_alert_policy (tenant_id, policy, updated_by, updated_at)
				 VALUES ($1,$2,$3,$4)`, r.tenant, r.body, r.by, r.at); err != nil {
				return fmt.Errorf("bgpwatch: import alert policy (tenant %s): %w", r.tenant, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}
