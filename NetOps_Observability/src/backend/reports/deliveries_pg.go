package reports

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// report_deliveries_pg.go — per-recipient delivery ledger. It lets a retried
// report skip recipients that already received it (resend only the failures).
// One row per (execution, recipient): an UPSERT that refuses to downgrade an
// 'ok' back to 'failed', so a success is sticky across attempts.
type PGDeliveryStore struct {
	db DB
}

func NewPGDeliveryStore(db DB) *PGDeliveryStore { return &PGDeliveryStore{db: db} }

// Record persists this attempt's per-recipient outcomes. Writes run platform-
// scoped (the worker is infrastructure); the tenant_id column keeps RLS reads
// scoped.
func (s *PGDeliveryStore) Record(ctx context.Context, tenant, execID string, ds []DeliveryStatus) error {
	if len(ds) == 0 {
		return nil
	}
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		for _, d := range ds {
			status := "failed"
			if d.OK {
				status = "ok"
			}
			at := d.At
			if at.IsZero() {
				at = time.Now().UTC()
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO report_execution_deliveries
					(id, tenant_id, execution_id, recipient, channel, status, attempt, error, at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
				ON CONFLICT (execution_id, recipient) DO UPDATE
				   SET status=EXCLUDED.status, attempt=EXCLUDED.attempt,
				       error=EXCLUDED.error, at=EXCLUDED.at
				 WHERE report_execution_deliveries.status <> 'ok'`,
				randHex(8), normTenant(tenant), execID, d.Recipient, d.Channel, status, d.Attempt, nullText(d.Error), at); err != nil {
				return err
			}
		}
		return nil
	})
}

// Delivered returns the set of recipients already successfully delivered for an
// execution, so a retry can skip them.
func (s *PGDeliveryStore) Delivered(ctx context.Context, execID string) (map[string]bool, error) {
	out := map[string]bool{}
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT recipient FROM report_execution_deliveries
			 WHERE execution_id=$1 AND status='ok'`, execID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r string
			if err := rows.Scan(&r); err != nil {
				return err
			}
			out[r] = true
		}
		return rows.Err()
	})
	return out, err
}

// DeliveryRecorder is the slice of the ledger the pipeline depends on (kept as an
// interface so the worker can be tested with a fake).
type DeliveryRecorder interface {
	Record(ctx context.Context, tenant, execID string, ds []DeliveryStatus) error
	Delivered(ctx context.Context, execID string) (map[string]bool, error)
}

var _ DeliveryRecorder = (*PGDeliveryStore)(nil)
