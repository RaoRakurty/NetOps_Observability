package configstore

// import.go — the one-time file→Postgres cutover for the config-version
// register (tracker 245 / the 2026-09-06 importer extension).
//
// The register is selected by STORE_BACKEND: on Postgres the api reads
// config_backup_versions and never opens config_backup_versions.json. Without
// this move a cutover leaves the sealed blobs on the volume with NOTHING
// referencing them — every captured configuration becomes unreachable and the
// drift baseline (the golden version) is gone.
//
// Stricter than NewFileStore, which starts empty over a corrupt file so a
// running install keeps serving. A migration that silently imported a subset
// would be indistinguishable from a complete one.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// importTimeout bounds the whole-collection write (§9).
const importTimeout = 2 * time.Minute

// CountRows reports how many version rows the Postgres target holds across
// every tenant (platform scope — the importer's own read).
func CountRows(ctx context.Context, db DB) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var n int
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM config_backup_versions`).Scan(&n)
	})
	return n, err
}

// ImportFile writes the file register into config_backup_versions, preserving
// the tenant, device, content address, capture time, blob reference, drift
// verdict AND the golden mark. Returns the number of rows written.
//
// The golden mark is imported in the same INSERT rather than through
// SetGolden: the database's partial unique index (one golden per device) is
// then the thing that catches a file holding two, and it does so by failing the
// import rather than by letting the last write win.
func ImportFile(ctx context.Context, db DB, raw []byte) (int, error) {
	var list []Version
	if err := json.Unmarshal(raw, &list); err != nil {
		return 0, fmt.Errorf("configstore: the version register file is malformed: %w", err)
	}
	for i := range list {
		list[i].TenantID = NormTenant(list[i].TenantID)
		if list[i].DeviceID == "" {
			return 0, fmt.Errorf("configstore: the register holds a version with no device id (sha %q)", list[i].SHA)
		}
		if list[i].Status == StatusOK && !validSHA(list[i].SHA) {
			return 0, fmt.Errorf("configstore: device %s holds a successful version with an invalid sha %q",
				list[i].DeviceID, list[i].SHA)
		}
		if list[i].CapturedAt.IsZero() {
			return 0, fmt.Errorf("configstore: device %s version %s has no capture time", list[i].DeviceID, list[i].SHA)
		}
	}
	if len(list) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, v := range list {
			if _, err := tx.Exec(ctx, `INSERT INTO config_backup_versions
			        (tenant_id, device_id, version_sha, captured_at, size_bytes, blob_ref,
			         vendor, status, error_text, golden, drift_state, lines_added, lines_removed)
			    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
				v.TenantID, v.DeviceID, v.SHA, v.CapturedAt, v.SizeBytes, v.BlobRef,
				v.Vendor, v.Status, v.Error, v.Golden, v.Drift, v.Added, v.Removed); err != nil {
				return fmt.Errorf("configstore: import version %s of device %s (tenant %s): %w",
					v.SHA, v.DeviceID, v.TenantID, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(list), nil
}
