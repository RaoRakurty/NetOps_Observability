package pcap

// import.go — the one-time file→Postgres cutover for the capture register
// (tracker 245 / the 2026-09-06 importer extension).
//
// The register is an INDEX over sealed capture blobs on the data volume. A
// cutover that lost it would leave every blob on disk with nothing referencing
// it: undownloadable, unprunable, and invisible to the audit trail that says a
// capture was taken. The blobs are customer payload, so orphaning them is a
// data-retention problem, not merely a lost list.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// importTimeout bounds the whole-collection write (§9).
const importTimeout = 2 * time.Minute

// CountRows reports how many capture rows the Postgres target holds across
// every tenant (platform scope — the importer's own read).
func CountRows(ctx context.Context, db DB) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var n int
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM pcap_captures`).Scan(&n)
	})
	return n, err
}

// ImportFile writes the file register into pcap_captures, preserving the owner,
// the minted capture id, the blob reference and every timestamp. Returns the
// number of rows written.
func ImportFile(ctx context.Context, db DB, raw []byte) (int, error) {
	var list []Capture
	if err := json.Unmarshal(raw, &list); err != nil {
		return 0, fmt.Errorf("pcap: the capture register file is malformed: %w", err)
	}
	for i := range list {
		list[i].TenantID = NormTenant(list[i].TenantID)
		if list[i].DeviceID == "" || !ValidateCaptureID(list[i].ID) {
			return 0, fmt.Errorf("pcap: the register holds a row with no device id or an invalid capture id (%q)", list[i].ID)
		}
		if list[i].StartedAt.IsZero() {
			return 0, fmt.Errorf("pcap: capture %s has no start time", list[i].ID)
		}
	}
	if len(list) == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, importTimeout)
	defer cancel()
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, c := range list {
			if _, err := tx.Exec(ctx, `INSERT INTO pcap_captures
			        (tenant_id, device_id, capture_id, iface, filter_expr, duration_s,
			         max_packets, started_at, expires_at, ended_at, status, packets,
			         bytes, error_text, blob_ref, actor, remote_path, platform)
			    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
				c.TenantID, c.DeviceID, c.ID, c.Interface, c.Filter, c.DurationSec,
				c.MaxPackets, c.StartedAt, c.ExpiresAt, c.EndedAt, c.Status, c.Packets,
				c.Bytes, c.Error, c.BlobRef, c.Actor, c.RemotePath, c.Platform); err != nil {
				return fmt.Errorf("pcap: import capture %s of device %s (tenant %s): %w",
					c.ID, c.DeviceID, c.TenantID, err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(list), nil
}
