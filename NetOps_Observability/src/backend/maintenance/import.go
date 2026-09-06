package maintenance

// import.go — the one-time file→Postgres cutover for maintenance windows
// (tracker 245 / the 2026-09-06 importer extension).
//
// A maintenance window SUPPRESSES alerts. Losing one on a backend switch does
// not fail quietly — it pages someone at 3am for planned work, which is the
// fastest way to teach a team to ignore the pager.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// importTimeout bounds the whole-collection write (§9).
const importTimeout = 2 * time.Minute

// CountRows reports how many window rows the Postgres target holds across every
// tenant (platform scope — the importer's own read).
func CountRows(ctx context.Context, db DB) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var n int
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM maintenance_windows`).Scan(&n)
	})
	return n, err
}

// ImportFile writes the file register into maintenance_windows, preserving each
// window's id, owner, schedule and timestamps. Returns the number of rows
// written.
func ImportFile(ctx context.Context, db DB, raw []byte) (int, error) {
	var list []Window
	if err := json.Unmarshal(raw, &list); err != nil {
		return 0, fmt.Errorf("maintenance: the windows file is malformed: %w", err)
	}
	perTenant := map[string]int{}
	for i := range list {
		list[i].TenantID = normTenant(list[i].TenantID)
		if list[i].ID == "" {
			return 0, fmt.Errorf("maintenance: the file holds a window with no id (tenant %q)", list[i].TenantID)
		}
		if err := list[i].Validate(); err != nil {
			return 0, fmt.Errorf("maintenance: window %s (tenant %s) is invalid: %w", list[i].ID, list[i].TenantID, err)
		}
		perTenant[list[i].TenantID]++
		if perTenant[list[i].TenantID] > MaxPerTenant {
			return 0, fmt.Errorf("maintenance: tenant %s holds more than the %d window cap — refusing to import a truncated set",
				list[i].TenantID, MaxPerTenant)
		}
	}
	if len(list) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, w := range list {
			blob, berr := jsonBlob(w)
			if berr != nil {
				return berr
			}
			created, updated := w.CreatedAt, w.UpdatedAt
			if created.IsZero() {
				created = time.Now().UTC()
			}
			if updated.IsZero() {
				updated = created
			}
			if _, err := tx.Exec(ctx, `INSERT INTO maintenance_windows
			        (tenant_id, window_id, name, enabled, data, created_by, created_at, updated_at)
			    VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
				w.TenantID, w.ID, w.Name, w.Enabled, blob, w.CreatedBy, created, updated); err != nil {
				return fmt.Errorf("maintenance: import window %s (tenant %s): %w", w.ID, w.TenantID, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(list), nil
}
