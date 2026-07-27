package chschema

// corr_retention.go — retention/tiering contract for the correlation history
// tables (#101, the deferred half of the #100 bounded-IO incident work).
//
// The 2026-07-09 incident left one class of unbounded growth unaddressed:
// corr_objects / corr_edges / corr_evidence (append-only version history) and
// corr_signals_archive (replay input, 29.9M rows at implementation time) grew
// forever by design, and corr_current accumulated one row per object EVER
// (closed objects never left the hot projection). This module makes hot
// retention explicit, env-driven, and profile-based, per
// docs/design/correlation-data-contract.md:
//
//	corr_current          — active objects + closed/merged for CLOSED_DAYS
//	corr_objects/edges/evidence — hot history for HISTORY_DAYS
//	corr_signals_archive  — hot replay input for ARCHIVE_DAYS
//
// History older than the hot horizon is NOT lost by contract: the cold-export
// job (scripts/ch-cold-export.sh, Parquet to data/clickhouse-cold/) runs ahead
// of the TTL horizon, so calibration (#67 P4), audit and offline replay keep
// the full archive. scripts/ch-retention-dry-run.sh previews exactly what a
// given profile would drop, and by when, before you enable it.
//
// Safety properties:
//   - ALTER ... MODIFY TTL is metadata-only here: materialize_ttl_after_modify=0
//     prevents a table-rewriting mutation on a live multi-million-row table.
//     Expiry happens via background part drops (ttl_only_drop_parts=1), i.e.
//     whole month-partitions age out at zero merge cost; effective retention
//     therefore lags the configured horizon by up to one partition month.
//   - A floor of 7 days is enforced on every knob: a typo'd env value can slow
//     retention down, never turn it into instant deletion.
//   - 0 disables a TTL knob explicitly (enterprise keep-forever contract) and
//     emits nothing — an existing TTL stays until removed operationally
//     (documented in docs/runbooks/correlation-retention-cold-archive.md).
//   - Statements are idempotent (re-applying the same TTL is a no-op metadata
//     write) and converge on every boot like the rest of corr_schema.go.

import (
	"log"
	"strconv"
)

// corrRetentionDays is the resolved per-tier hot retention, in days.
// Zero means "no TTL" for that tier (keep forever, explicit contract).
type corrRetentionDays struct {
	History int // corr_objects, corr_edges, corr_evidence (version history)
	Archive int // corr_signals_archive (replay input)
	Closed  int // corr_current rows whose state left 'open'
}

// corrRetentionProfiles: environment presets. Chosen so that the DEFAULT
// (production) is generous enough that enabling it on an existing deployment
// gives the cold-export cron weeks of runway before the first part drops.
var corrRetentionProfiles = map[string]corrRetentionDays{
	"lab":        {History: 90, Archive: 45, Closed: 60},
	"demo":       {History: 30, Archive: 14, Closed: 30},
	"production": {History: 180, Archive: 90, Closed: 90},
	// Enterprise extended-retention contract: long finite horizons; raise the
	// knobs (or set 0 = keep forever) per contract instead of inventing a
	// bigger profile.
	"extended": {History: 730, Archive: 365, Closed: 365},
}

// CorrRetentionConfig resolves the retention profile + per-knob overrides from
// the environment. Invalid values fall back to the profile; sub-floor values
// are clamped up (a typo must never become instant deletion).
func CorrRetentionConfig() corrRetentionDays {
	const floorDays = 7
	profile := envOr("CORR_RETENTION_PROFILE", "production")
	days, ok := corrRetentionProfiles[profile]
	if !ok {
		log.Printf("corr-retention: unknown CORR_RETENTION_PROFILE %q, using production", profile)
		days = corrRetentionProfiles["production"]
	}
	knob := func(env string, def int) int {
		raw := envOr(env, "")
		if raw == "" {
			return def
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			log.Printf("corr-retention: invalid %s=%q, using profile value %d", env, raw, def)
			return def
		}
		if n > 0 && n < floorDays {
			log.Printf("corr-retention: %s=%d below %d-day safety floor, clamping", env, n, floorDays)
			return floorDays
		}
		return n
	}
	return corrRetentionDays{
		History: knob("CORR_RETENTION_HISTORY_DAYS", days.History),
		Archive: knob("CORR_RETENTION_ARCHIVE_DAYS", days.Archive),
		Closed:  knob("CORR_RETENTION_CLOSED_DAYS", days.Closed),
	}
}

// CorrRetentionDDL renders the converge statements for the resolved retention
// config. Appended to the corr schema converge list on every API boot (same
// idempotent, best-effort contract as CorrSchemaDDL).
func CorrRetentionDDL(d corrRetentionDays) []string {
	var stmts []string
	// Part-level expiry only: month-partitions drop whole, no TTL merges.
	// (corr_current is deliberately NOT here — its TTL is row-level WHERE.)
	for _, t := range []string{"corr_objects", "corr_edges", "corr_evidence", "corr_signals_archive"} {
		stmts = append(stmts, "ALTER TABLE netops."+t+" MODIFY SETTING ttl_only_drop_parts = 1")
	}
	ttl := func(table, expr string, days int) {
		stmts = append(stmts,
			"ALTER TABLE netops."+table+" MODIFY TTL "+expr+" + INTERVAL "+
				strconv.Itoa(days)+" DAY SETTINGS materialize_ttl_after_modify = 0")
	}
	if d.History > 0 {
		ttl("corr_objects", "toDateTime(created_at)", d.History)
		ttl("corr_edges", "toDateTime(created_at)", d.History)
		ttl("corr_evidence", "toDateTime(created_at)", d.History)
	}
	if d.Archive > 0 {
		ttl("corr_signals_archive", "toDateTime(ts)", d.Archive)
	}
	if d.Closed > 0 {
		// Row-level: only rows that left 'open' expire. An abandoned 'open' row
		// (engine restart lost the in-memory registry) is repaired — not
		// deleted — by the corr_current reconciler (corr_current_reconcile.go).
		stmts = append(stmts,
			"ALTER TABLE netops.corr_current MODIFY TTL toDateTime(created_at) + INTERVAL "+
				strconv.Itoa(d.Closed)+" DAY DELETE WHERE state != 'open' SETTINGS materialize_ttl_after_modify = 0")
	}
	return stmts
}
