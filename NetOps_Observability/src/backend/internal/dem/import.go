// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dem

// import.go — the one-time file→Postgres cutover for the target catalogue
// (tracker 245 / the 2026-09-06 importer extension).
//
// The catalogue is selected by STORE_BACKEND: on Postgres the api reads
// dem_targets and NEVER looks at dem_targets.json, so an install that switches
// backends with targets on disk stops measuring every one of them, silently.
// This is the move that keeps them.
//
// It is deliberately STRICTER than NewFileStore. The file store drops a bad row
// and records LoadErr, because a running install must keep serving; a MIGRATION
// must not, because a dropped row here is data the operator never gets back and
// the boot log is the only place it could have been mentioned. Anything it
// cannot import exactly is an error, and the api refuses to boot naming this
// collection.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// importTimeout bounds the whole-collection write (§9: all IO has a timeout).
// It is deliberately far larger than pgTimeout: this is one transaction over an
// entire install's catalogue, run once, at boot, before the listener opens.
const importTimeout = 2 * time.Minute

// CountRows reports how many catalogue rows the Postgres target holds, across
// every tenant. Platform scope ('*') — this is the importer's own read, not a
// caller's, and it must see rows no tenant scope would.
func CountRows(ctx context.Context, db DB) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var n int
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM dem_targets`).Scan(&n)
	})
	return n, err
}

// ImportFile writes the file backend's catalogue into dem_targets, preserving
// each target's id, owning tenant and timestamps verbatim. Returns the number
// of rows written.
//
// The per-tenant cap is NOT applied: a catalogue that was legal on the file
// backend must arrive whole, and silently truncating it at MaxTargetsPerTenant
// would lose targets an operator can still see in the file. A file over the cap
// is refused instead, with the tenant named, so the operator decides.
func ImportFile(ctx context.Context, db DB, raw []byte) (int, error) {
	var buckets map[string][]Target
	if err := json.Unmarshal(raw, &buckets); err != nil {
		return 0, fmt.Errorf("dem: the target catalogue file is malformed: %w", err)
	}
	type row struct {
		tenant string
		tgt    Target
		data   []byte
	}
	rows := []row{}
	for rawTenant, list := range buckets {
		tenant, err := concreteTenant(rawTenant)
		if err != nil {
			return 0, fmt.Errorf("dem: the target catalogue file holds a non-concrete tenant bucket %q", rawTenant)
		}
		if len(list) > MaxTargetsPerTenant {
			return 0, fmt.Errorf("dem: tenant %s holds %d targets, over the %d cap — refusing to import a truncated catalogue",
				tenant, len(list), MaxTargetsPerTenant)
		}
		for _, tgt := range list {
			// The BUCKET is authoritative for ownership, exactly as the file
			// store treats it: a row's own tenant field is never trusted to
			// move it into another tenant's scope (§3a rule 2).
			tgt.TenantID = tenant
			if tgt.ID == "" {
				return 0, fmt.Errorf("dem: tenant %s holds a target with no id", tenant)
			}
			if err := tgt.Validate(); err != nil {
				return 0, fmt.Errorf("dem: tenant %s target %s is invalid: %w", tenant, tgt.ID, err)
			}
			data, err := json.Marshal(tgt)
			if err != nil {
				return 0, err
			}
			rows = append(rows, row{tenant: tenant, tgt: tgt, data: data})
		}
	}
	if len(rows) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	// ONE transaction under platform scope: either the whole catalogue arrives
	// or none of it does. A half-imported catalogue would be recorded as done.
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, r := range rows {
			if _, err := tx.Exec(ctx,
				`INSERT INTO dem_targets (tenant_id, target_id, name, kind, site, app, paused, data, created_by, created_at, updated_at)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
				r.tenant, r.tgt.ID, r.tgt.Name, r.tgt.Kind, r.tgt.Site, r.tgt.App,
				r.tgt.Paused, r.data, r.tgt.CreatedBy, r.tgt.CreatedAt, r.tgt.UpdatedAt); err != nil {
				return fmt.Errorf("dem: import target %s (tenant %s): %w", r.tgt.ID, r.tenant, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}
