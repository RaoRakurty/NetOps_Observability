package main

import (
	"context"
	"netops/backend/internal/platformdb"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/safego"
)

// audit_retention.go — bounded growth for the Postgres audit trail (audit F-57).
//
// The finding has two halves and this file closes the second one.
//
//   - Observability (audit.go / audit_pg.go): the trail grew without bound
//     while the read path was capped, so the UI could never reflect its size.
//     Fixed by reporting the TRUE count on every read.
//   - Retention (here): `nms_store.go` held the ONLY time-based DELETE in the
//     entire non-test Go tree. The file audit backend self-bounds to a
//     5,000-event ring (auditMaxEvents); the Postgres backend had no
//     counterpart at all — 29,002 rows / 13 MB and +597/day at audit time.
//
// Deliberately OPT-IN and OFF by default. An audit trail is evidence: deleting
// it on a default no operator chose would be a worse defect than the growth,
// and retention periods are a compliance decision, not an engineering one. Set
// AUDIT_RETENTION_DAYS to a positive number to enable; 0/unset keeps forever
// (and the read path now makes that choice visible).
//
// The sweep is deliberately NOT the `saveRows`/`pgstore.go` path, which issues
// `DELETE FROM <table>` with no WHERE under platform scope — audit_events is a
// registered rowSpec there, so a flush through that path would truncate the
// whole cross-tenant trail. This sweep is always WHERE-bounded on ts, capped
// per run, and logs exactly what it removed.

const (
	auditRetentionEnv = "AUDIT_RETENTION_DAYS"
	// auditSweepInterval is how often the sweeper runs. Retention is a
	// long-horizon property; hourly is ample and keeps each DELETE small.
	auditSweepInterval = time.Hour
	// auditSweepBatch bounds ONE delete so a first run against a long-neglected
	// table cannot lock it for minutes. Whatever is left is removed next hour.
	auditSweepBatch = 10000
)

// auditRetentionDays reads the configured retention. Returns 0 when retention
// is disabled (unset, empty, zero, negative, or unparseable — an operator typo
// must never be read as "delete everything").
func auditRetentionDays() int {
	raw := os.Getenv(auditRetentionEnv)
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		if err != nil {
			logError("audit", "invalid "+auditRetentionEnv+" — retention stays OFF", map[string]any{"value": raw})
		}
		return 0
	}
	return n
}

// sweepAuditRetention deletes at most auditSweepBatch rows older than `days`
// and returns how many it removed. Platform scope ('*'): the trail spans every
// tenant, and retention is a platform-wide policy.
func sweepAuditRetention(ctx context.Context, db *platformdb.DB, days int) (int64, error) {
	if db == nil || days <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	var removed int64
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM audit_events
			 WHERE id IN (SELECT id FROM audit_events WHERE ts < $1 ORDER BY ts LIMIT $2)`,
			cutoff, auditSweepBatch)
		if err != nil {
			return err
		}
		removed = tag.RowsAffected()
		return nil
	})
	return removed, err
}

// startAuditRetention launches the hourly sweeper when AUDIT_RETENTION_DAYS is
// set and the Postgres backend is active. A no-op otherwise, and it never takes
// the API down: the goroutine runs under safego and every failure is logged.
func startAuditRetention(ctx context.Context) {
	days := auditRetentionDays()
	ps, ok := platformdb.ActivePG()
	if !ok || ps == nil || days <= 0 {
		return
	}
	logInfo("audit", "retention enabled", map[string]any{"retention_days": days, "batch": auditSweepBatch})
	safego.Go("audit-retention", func() {
		t := time.NewTicker(auditSweepInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sctx, cancel := context.WithTimeout(ctx, 60*time.Second)
				removed, err := sweepAuditRetention(sctx, ps.DB(), days)
				cancel()
				if err != nil {
					logError("audit", "retention sweep", map[string]any{"error": err.Error()})
					continue
				}
				if removed > 0 {
					logInfo("audit", "retention sweep removed events", map[string]any{
						"removed": removed, "retention_days": days,
					})
				}
			}
		}
	})
}
