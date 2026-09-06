// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package metering

// import.go — the one-time file→Postgres cutover for the metering history
// (tracker 245 / the 2026-09-06 importer extension).
//
// The store is selected by STORE_BACKEND: on Postgres the api reads
// metering_daily and never opens /data/api/metering.json. Nothing GATES on
// metering — losing it cannot refuse a device — but a usage report is the
// evidence a true-up conversation runs on, and history that is silently gone is
// history neither side can recompute. It travels.
//
// The rows land verbatim: same day key, same owning tenant, same sample count,
// same meters. Folding them through Record() would re-derive numbers the
// customer has already been shown, which is precisely what a signed report
// promises will not happen.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// importTimeout bounds the whole-collection write (§9). The history is bounded
// at RetentionDays rows per tenant, so this is a small, once-per-install write.
const importTimeout = 2 * time.Minute

// CountRows reports how many daily rows the Postgres target holds (platform
// scope — the installation's own number, never a tenant's).
func CountRows(ctx context.Context, db DB) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	n := 0
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM metering_daily`).Scan(&n)
	})
	return n, err
}

// ImportFile writes the file history into metering_daily. Returns the number of
// rows written.
//
// The installation row (tenant_id = ScopeInstallation, the empty string) is
// imported like any other: it is the row that records how many tenants and orgs
// the installation had, and only the '*' platform scope can ever read it.
func ImportFile(ctx context.Context, db DB, raw []byte) (int, error) {
	var f meteringFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, fmt.Errorf("metering: the usage history file is malformed: %w", err)
	}
	seen := map[string]bool{}
	for i := range f.Records {
		f.Records[i].TenantID = NormaliseTenant(f.Records[i].TenantID)
		if !ValidDay(f.Records[i].Day) {
			return 0, fmt.Errorf("metering: the history holds a row with an invalid day key %q (tenant %q)",
				f.Records[i].Day, f.Records[i].TenantID)
		}
		// (tenant, day) is the primary key. A duplicate in the file would be
		// silently collapsed by the database; refusing names the collision
		// instead of losing a row's meters to it.
		k := f.Records[i].TenantID + "\x00" + f.Records[i].Day
		if seen[k] {
			return 0, fmt.Errorf("metering: the history holds two rows for tenant %q on %s",
				f.Records[i].TenantID, f.Records[i].Day)
		}
		seen[k] = true
	}
	if len(f.Records) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, r := range f.Records {
			body, merr := json.Marshal(r)
			if merr != nil {
				return merr
			}
			at := r.UpdatedAt
			if at.IsZero() {
				at = time.Now().UTC()
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO metering_daily (tenant_id, day, samples, updated_at, data)
				VALUES ($1, $2, $3, $4, $5)`,
				r.TenantID, r.Day, r.Samples, at.UTC(), body); err != nil {
				return fmt.Errorf("metering: import row %s (tenant %q): %w", r.Day, r.TenantID, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(f.Records), nil
}
