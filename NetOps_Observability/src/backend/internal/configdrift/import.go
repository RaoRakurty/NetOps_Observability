// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configdrift

// import.go — the one-time file→Postgres cutover for the drift-state register
// (tracker 245 / the 2026-09-06 importer extension).
//
// Drift state is DERIVED — the next capture rebuilds it — but it is also the
// inventory sync badge, and a cutover that dropped it would render every device
// `unknown` until each one had been captured again. That reads as "we have not
// assessed you", which is exactly what the state vocabulary exists to say
// honestly rather than by accident.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// importTimeout bounds the whole-collection write (§9).
const importTimeout = 2 * time.Minute

// CountRows reports how many drift rows the Postgres target holds across every
// tenant (platform scope — the importer's own read).
func CountRows(ctx context.Context, db DB) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var n int
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM config_drift_state`).Scan(&n)
	})
	return n, err
}

// ImportFile writes the file register into config_drift_state, preserving the
// owner, the verdict and every timestamp. Returns the number of rows written.
func ImportFile(ctx context.Context, db DB, raw []byte) (int, error) {
	var list []State
	if err := json.Unmarshal(raw, &list); err != nil {
		return 0, fmt.Errorf("configdrift: the drift-state file is malformed: %w", err)
	}
	for i := range list {
		list[i].TenantID = NormTenant(list[i].TenantID)
		if list[i].DeviceID == "" {
			return 0, fmt.Errorf("configdrift: the register holds a state row with no device id")
		}
	}
	if len(list) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, st := range list {
			// The nullable stamps stay NULL when the file has no value: a zero
			// time written as a real timestamp would claim a capture that never
			// happened.
			var lastCap, changed *time.Time
			if !st.LastCapture.IsZero() {
				t := st.LastCapture.UTC()
				lastCap = &t
			}
			if !st.ChangedAt.IsZero() {
				t := st.ChangedAt.UTC()
				changed = &t
			}
			updated := st.UpdatedAt
			if updated.IsZero() {
				updated = time.Now().UTC()
			}
			if _, err := tx.Exec(ctx, `INSERT INTO config_drift_state
			        (tenant_id, device_id, state, last_sha, golden_sha, lines_added,
			         lines_removed, last_error, last_capture_at, changed_at, updated_at)
			    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
				st.TenantID, st.DeviceID, st.State, st.LastSHA, st.GoldenSHA, st.Added,
				st.Removed, st.LastError, lastCap, changed, updated.UTC()); err != nil {
				return fmt.Errorf("configdrift: import state of device %s (tenant %s): %w",
					st.DeviceID, st.TenantID, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(list), nil
}
