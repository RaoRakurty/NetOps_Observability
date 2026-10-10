// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chschema

// ch_sql.go — pure SQL/DDL fragments shared across the schema statements.
// They live here because this package OWNS the schema: a statement the boot
// convergence emits should be defined next to the table it targets, not in the
// handler file that happens to also use it.

import "os"

// envOr reads an env knob with a default. chschema owns its own retention
// knobs (CH_RETENTION_* / CORR_RETENTION_PROFILE), so it reads them directly
// rather than taking a config struct it would only ever be handed from env.
// Deliberately duplicated rather than shared via a "utils" package, which
// CLAUDE.md §2 forbids outright.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ISO wraps a ClickHouse DateTime/DateTime64 SQL expression (a column, or an
// aggregate like max(ts)) so it is SELECTed as an RFC 3339 UTC string
// (log-time standard, docs/design/log-time-standard.md rule R1 / slice S3).
//
// ClickHouse's toString(DateTime64) renders a ZONE-LESS string
// ("2026-07-16 21:56:03.562") in the server timezone. JavaScript — and any
// naive consumer — parses such strings as LOCAL time, which is exactly the
// mixed-zone display defect audited as F11/F12. Every ClickHouse-backed
// SELECT therefore renders datetimes with ISO: explicit UTC, RFC 3339
// ("2026-07-16T21:56:03.562Z"), so the instant is unambiguous on the wire
// regardless of the ClickHouse server timezone. Sub-second precision follows
// the column type, exactly as toString did.
//
// Server-side consumers of these strings (parseChTS, parseCHTime,
// ticketing/report layouts) accept both RFC 3339 and the legacy zone-less
// form, so mixed fleets during rollout stay readable.
func ISO(expr string) string {
	return "concat(replaceOne(toString(" + expr + ", 'UTC'), ' ', 'T'), 'Z')"
}

// StrictRowPolicyDDL is the STRICT tenant row policy: a row is visible only to
// its own tenant, or to a caller that explicitly asked for the cross-tenant
// scope. No lenient untagged-shared escape — that distinction is asserted by
// the corr-family guard tests.
func StrictRowPolicyDDL(table string) string {
	return "CREATE ROW POLICY OR REPLACE tenant_iso_" + table + " ON netops." + table +
		" USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__' TO ALL"
}

// The narrow corr_current INSERT is assembled from a head, the created_at
// expression and a tail so the two repair flavours share every other column:
//
//   - CorrCurrentNarrowInsertPrefix copies history's own created_at (the drift
//     repair and the boot backfill: the projection row is older than history,
//     so history's timestamp already wins the ReplacingMergeTree(created_at)
//     fold).
//   - CorrCurrentRestampedInsertPrefix stamps now64(3) (the state repair: the
//     stale projection row can be NEWER than history — a heartbeat touch writes
//     corr_current only, with a fresh created_at — so re-inserting history's
//     older timestamp would lose the fold and repair nothing; tracker 328).
//
// Both key the picked rows by (tenant, id, version, created_at): engine
// restarts reset version counters, so (tenant, id, version) alone can match
// two history rows and re-project the stale one.
const corrCurrentInsertHead = `INSERT INTO netops.corr_current
    (tenant_id, correlation_id, version, state, window_start, window_end,
     top_hypothesis, top_confidence, verdict_tier, evidence_missing, affected,
     signal_count, node_count, engine_version, catalog_version, merged_into,
     created_at, owner, plane_count, debug_excluded, low_authority, seam_type)
SELECT o.tenant_id, o.correlation_id, o.version, o.state, o.window_start, o.window_end,
       o.top_hypothesis, o.top_confidence, o.verdict_tier, o.evidence_missing, o.affected,
       o.signal_count, o.node_count, o.engine_version, o.catalog_version, o.merged_into,
       `

const corrCurrentInsertTail = `
       JSONExtractString(o.hypotheses,'ranking','hypotheses',1,'verdict','owner'),
       toUInt8(length(JSONExtract(o.hypotheses,'ranking','hypotheses',1,'verdict','modality_coverage','Array(String)'))),
       toUInt8(length(JSONExtract(o.hypotheses,'ranking','hypotheses',1,'verdict','excluded_debug_probes','Array(String)')) > 0),
       toUInt8(length(JSONExtract(o.hypotheses,'ranking','hypotheses',1,'verdict','low_authority_probe_scopes','Array(String)')) > 0),
       -- Tracker 197: the same extraction the time-intelligence fold used to do
       -- per page. Done ONCE here, on the repair path that already reads the
       -- blob, so a row this reconciler writes carries the grounded seam type
       -- instead of the '' an un-backfilled row would keep.
       JSONExtractString(o.hypotheses,'grounding_context','seams',1,'seam_type')
  FROM netops.corr_objects AS o
 WHERE (o.tenant_id, o.correlation_id, o.version, o.created_at) IN (`

// CorrCurrentNarrowInsertPrefix re-projects picked history rows with their own
// created_at. The pick must yield (tenant_id, correlation_id, version, created_at).
const CorrCurrentNarrowInsertPrefix = corrCurrentInsertHead + `o.created_at,` + corrCurrentInsertTail

// CorrCurrentRestampedInsertPrefix re-projects picked history rows stamped
// now64(3), so the repaired row wins the fold over a newer stale row.
const CorrCurrentRestampedInsertPrefix = corrCurrentInsertHead + `now64(3),` + corrCurrentInsertTail

func CorrCurrentBackfillSQL() string {
	return CorrCurrentNarrowInsertPrefix + `
       SELECT tenant_id, correlation_id, version, created_at
         FROM netops.corr_objects
        WHERE (tenant_id, correlation_id) NOT IN
              (SELECT tenant_id, correlation_id FROM netops.corr_current)
        ORDER BY tenant_id, correlation_id, created_at DESC
        LIMIT 1 BY tenant_id, correlation_id)`
}
