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

// StrictRowPolicyDDL is the STRICT tenant row policy: a row is visible only to
// its own tenant, or to a caller that explicitly asked for the cross-tenant
// scope. No lenient untagged-shared escape — that distinction is asserted by
// the corr-family guard tests.
func StrictRowPolicyDDL(table string) string {
	return "CREATE ROW POLICY OR REPLACE tenant_iso_" + table + " ON netops." + table +
		" USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__' TO ALL"
}

const CorrCurrentNarrowInsertPrefix = `INSERT INTO netops.corr_current
    (tenant_id, correlation_id, version, state, window_start, window_end,
     top_hypothesis, top_confidence, verdict_tier, evidence_missing, affected,
     signal_count, node_count, engine_version, catalog_version, merged_into,
     created_at, owner, plane_count, debug_excluded, low_authority)
SELECT o.tenant_id, o.correlation_id, o.version, o.state, o.window_start, o.window_end,
       o.top_hypothesis, o.top_confidence, o.verdict_tier, o.evidence_missing, o.affected,
       o.signal_count, o.node_count, o.engine_version, o.catalog_version, o.merged_into,
       o.created_at,
       JSONExtractString(o.hypotheses,'ranking','hypotheses',1,'verdict','owner'),
       toUInt8(length(JSONExtract(o.hypotheses,'ranking','hypotheses',1,'verdict','modality_coverage','Array(String)'))),
       toUInt8(length(JSONExtract(o.hypotheses,'ranking','hypotheses',1,'verdict','excluded_debug_probes','Array(String)')) > 0),
       toUInt8(length(JSONExtract(o.hypotheses,'ranking','hypotheses',1,'verdict','low_authority_probe_scopes','Array(String)')) > 0)
  FROM netops.corr_objects AS o
 WHERE (o.tenant_id, o.correlation_id, o.version) IN (`

func CorrCurrentBackfillSQL() string {
	return CorrCurrentNarrowInsertPrefix + `
       SELECT tenant_id, correlation_id, version
         FROM netops.corr_objects
        WHERE (tenant_id, correlation_id) NOT IN
              (SELECT tenant_id, correlation_id FROM netops.corr_current)
        ORDER BY tenant_id, correlation_id, version DESC
        LIMIT 1 BY tenant_id, correlation_id)`
}
