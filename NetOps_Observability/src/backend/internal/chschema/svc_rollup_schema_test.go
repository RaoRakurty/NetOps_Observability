package chschema

// svc_rollup_schema_test.go — contract pins for the #69 P2 rollup + PBH V1
// baseline schema. Each assertion guards a design decision the rollup worker,
// backfill job and health/path readers depend on.

import (
	"strings"
	"testing"
)

func TestSvcRollupSchemaPins(t *testing.T) {
	ddl := strings.Join(SvcRollupSchemaDDL(), "\n")

	// Idempotent converge (runs on every boot).
	if !strings.Contains(ddl, "CREATE TABLE IF NOT EXISTS netops.svc_flow_rollup_1m") {
		t.Fatal("rollup CREATE must be IF NOT EXISTS (boot converge)")
	}
	// SummingMergeTree over exactly the three counters.
	if !strings.Contains(ddl, "SummingMergeTree((bytes, packets, flows))") {
		t.Error("rollup must be a SummingMergeTree over (bytes, packets, flows)")
	}
	// Tenant leads partition AND sort key: one row can only belong to one tenant,
	// and parts are per-tenant droppable (#20 Phase 3).
	if !strings.Contains(ddl, "PARTITION BY (tenant_id, toYYYYMMDD(minute))") {
		t.Error("tenant_id must lead PARTITION BY")
	}
	if !strings.Contains(ddl, "ORDER BY (tenant_id, minute, service_id, selector_version, seam_id, rolled_by)") {
		t.Error("sort key must be (tenant_id, minute, service_id, selector_version, seam_id, rolled_by)")
	}
	// service_id is Nullable in the sort key (§3.2) → allow_nullable_key required.
	if !strings.Contains(ddl, "service_id       Nullable(UUID)") {
		t.Error("service_id must be Nullable(UUID) from day one (§3.2 no-schema-churn)")
	}
	if !strings.Contains(ddl, "allow_nullable_key = 1") {
		t.Error("Nullable service_id in the sort key needs allow_nullable_key = 1")
	}
	// selector_version + rolled_by are the §3.3 attribution/checkpoint contract.
	for _, col := range []string{"selector_version UInt32", "rolled_by"} {
		if !strings.Contains(ddl, col) {
			t.Errorf("rollup schema missing %q", col)
		}
	}
	// STRICT policy — attributed traffic is tenant data; the lenient
	// untagged-shared escape would leak platform rows into every tenant.
	if !strings.Contains(ddl, "CREATE ROW POLICY OR REPLACE tenant_iso_svc_flow_rollup_1m") {
		t.Error("rollup needs the STRICT row policy")
	}
	if strings.Contains(ddl, "tenant_iso_svc_flow_rollup_1m ON netops.svc_flow_rollup_1m USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__' OR tenant_id = ''") {
		t.Error("rollup policy must NOT carry the lenient untagged-shared clause")
	}
	// NEVER a materialized view over flows (the flows_hourly regression).
	if strings.Contains(strings.ToUpper(ddl), "MATERIALIZED VIEW") {
		t.Fatal("no materialized view may exist in the rollup schema (flows_hourly regression)")
	}
}

// Both new DDL sets must ride the boot converge list, and init.sql (the
// fresh-install authority) must carry the same tables — the 2026-07-04 lesson:
// a live ALTER/CREATE that misses init.sql 500s the first virgin install.
