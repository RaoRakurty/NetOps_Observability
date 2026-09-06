// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package audit

import (
	"context"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/applog"
	"netops/backend/safego"
)

// retention.go — bounded growth for the Postgres audit trail (audit F-57).
//
// The finding has two halves and this file closes the second one.
//
//   - Observability (store.go / pg.go): the trail grew without bound
//     while the read path was capped, so the UI could never reflect its size.
//     Fixed by reporting the TRUE count on every read.
//   - Retention (here): `nms_store.go` held the ONLY time-based DELETE in the
//     entire non-test Go tree. The file audit backend self-bounds to a
//     5,000-event ring (maxEvents); the Postgres backend had no
//     counterpart at all — 29,002 rows / 13 MB and +597/day at audit time.
//
// Deliberately OPT-IN and OFF by default. An audit trail is evidence: deleting
// it on a default no operator chose would be a worse defect than the growth,
// and retention periods are a compliance decision, not an engineering one. Set
// AUDIT_RETENTION_DAYS to a positive number to enable; 0/unset keeps forever
// (and the read path now makes that choice visible). The env read itself stays
// in main; this package receives the raw value via ParseRetentionDays.
//
// The sweep is deliberately NOT the platformdb saveRows path, which issues
// `DELETE FROM <table>` with no WHERE under platform scope — audit_events is a
// registered rowSpec there, so a flush through that path would truncate the
// whole cross-tenant trail. This sweep is always WHERE-bounded on ts, capped
// per run, and logs exactly what it removed.

const (
	// sweepInterval is how often the sweeper runs. Retention is a
	// long-horizon property; hourly is ample and keeps each DELETE small.
	sweepInterval = time.Hour
	// sweepBatch bounds ONE delete so a first run against a long-neglected
	// table cannot lock it for minutes. Whatever is left is removed next hour.
	sweepBatch = 10000
)

// TxRunner is the slice of the platform DB the sweeper needs — satisfied by
// *platformdb.DB.WithTenant directly.
type TxRunner interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// ParseRetentionDays reads the configured retention from the raw env value.
// Returns 0 when retention is disabled (unset, empty, zero, negative, or
// unparseable — an operator typo must never be read as "delete everything").
func ParseRetentionDays(raw string) int {
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		if err != nil {
			applog.Error("audit", "invalid AUDIT_RETENTION_DAYS — retention stays OFF", map[string]any{"value": raw})
		}
		return 0
	}
	return n
}

// platformFloorSQL is the predicate that recognizes a PLATFORM-GLOBAL CONFIG
// CHANGE row — the same class the file backend's retained trail protects
// (platformtrail.go), expressed over the stored JSONB.
//
// It is fully PARAMETERIZED: the method list and the path prefixes are bound as
// arrays, never spliced into the statement, so the closed list in
// platformtrail.go cannot become SQL. The prefixes carry no LIKE metacharacter
// (pinned by TestPlatformPrefixesAreLiteralForLIKE), so `LIKE prefix || '%'` is
// an exact prefix test.
const platformFloorSQL = `(data->>'method' = ANY($3) AND data->>'path' LIKE ANY($4))`

// platformLikePatterns renders the closed prefix list as LIKE patterns.
func platformLikePatterns() []string {
	out := make([]string, 0, len(platformPathPrefixes))
	for _, p := range platformPathPrefixes {
		out = append(out, p+"%")
	}
	return out
}

// mutatingMethods is the method list the platform-change predicate matches,
// kept identical to IsPlatformChange's switch.
var mutatingMethods = []string{"POST", "PUT", "PATCH", "DELETE"}

// SweepRetention deletes at most sweepBatch rows older than `days` and returns
// how many it removed. Platform scope ('*'): the trail spans every tenant, and
// retention is a platform-wide policy.
//
// platformDays is the FLOOR under the platform-global config changes (tracker
// 235): a row that records a change to auth providers, LLM keys, token policy,
// notification channels or stack config is kept for at least that long even
// when `days` is shorter. Without it, turning retention on with a short horizon
// would delete exactly the events the 2026-09-03 incident could not answer
// without — and it would do it silently, months before anyone asked.
// platformDays <= 0, or <= days, means no separate floor.
func SweepRetention(ctx context.Context, db TxRunner, days, platformDays int) (int64, error) {
	if db == nil || days <= 0 {
		return 0, nil
	}
	now := time.Now().UTC()
	cutoff := now.AddDate(0, 0, -days)
	platformCutoff := cutoff
	if platformDays > days {
		platformCutoff = now.AddDate(0, 0, -platformDays)
	}
	var removed int64
	err := db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		// One statement, two horizons: an ordinary row goes at `cutoff`, a
		// platform-change row not before `platformCutoff`.
		tag, err := tx.Exec(ctx, `DELETE FROM audit_events
			 WHERE id IN (
				SELECT id FROM audit_events
				 WHERE (ts < $1 AND NOT `+platformFloorSQL+`)
				    OR (ts < $5 AND `+platformFloorSQL+`)
				 ORDER BY ts LIMIT $2)`,
			cutoff, sweepBatch, mutatingMethods, platformLikePatterns(), platformCutoff)
		if err != nil {
			return err
		}
		removed = tag.RowsAffected()
		return nil
	})
	return removed, err
}

// StartRetention launches the hourly sweeper. A no-op when days<=0 or db is
// absent, and it never takes the API down: the goroutine runs under safego and
// every failure is logged. The caller (main) gates on the Postgres backend
// being active and supplies the parsed retention.
func StartRetention(ctx context.Context, db TxRunner, days, platformDays int) {
	if db == nil || days <= 0 {
		return
	}
	applog.Info("audit", "retention enabled", map[string]any{
		"retention_days": days, "platform_retention_days": platformDays, "batch": sweepBatch})
	safego.Go("audit-retention", func() {
		t := time.NewTicker(sweepInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sctx, cancel := context.WithTimeout(ctx, 60*time.Second)
				removed, err := SweepRetention(sctx, db, days, platformDays)
				cancel()
				if err != nil {
					applog.Error("audit", "retention sweep", map[string]any{"error": err.Error()})
					continue
				}
				if removed > 0 {
					applog.Info("audit", "retention sweep removed events", map[string]any{
						"removed": removed, "retention_days": days,
					})
				}
			}
		}
	})
}
