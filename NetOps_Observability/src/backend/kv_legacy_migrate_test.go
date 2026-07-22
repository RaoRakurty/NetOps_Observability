package main

import (
	"testing"
)

// kv_legacy_migrate_test.go — the F-63 fix orphaned live data on the Postgres
// backend, and nothing caught it because the defect and its fix are each
// invisible from the other's environment. These tests pin the recovery.

// This file reuses the memKV backend and withBackend helper from
// kvstore_test.go rather than defining its own — one fake per seam.

// TestMigrateRecoversOrphanedLegacyKeys is the exact production shape: the
// legacy relative key holds the tenant's real governance config and the new
// /data/ key holds nothing, so every surface reads empty until this runs.
func TestMigrateRecoversOrphanedLegacyKeys(t *testing.T) {
	k := newMemKV()
	withBackend(t, k)

	live := []byte(`{"t_1":{"tenant_id":"t_1","rca_window_hours":10,"required_tags":["env","owner"]}}`)
	k.m["tenant_governance.json"] = live

	recovered := migrateLegacyKVKeys()

	got, err := kvLoad(tenantGovernancePath())
	if err != nil || string(got) != string(live) {
		t.Fatalf("governance at %s = (%q, %v), want the legacy value recovered.\n"+
			"Without this the F-63 key rename reads as total loss of every tenant's "+
			"required tags, RCA window and seam owners.", tenantGovernancePath(), got, err)
	}
	if len(recovered) == 0 {
		t.Fatal("migration recovered data but reported nothing — the operator has no way to know it happened")
	}

	// COPY, not move: the legacy row survives as a backup.
	if _, err := kvLoad("tenant_governance.json"); err != nil {
		t.Fatal("legacy key was removed — the migration must be reversible")
	}
}

// TestMigrateNeverOverwritesLiveData: if the current key already holds
// something, it is authoritative. Copying a stale legacy row over live config
// would be a second, worse data-loss event caused by the repair itself.
func TestMigrateNeverOverwritesLiveData(t *testing.T) {
	k := newMemKV()
	withBackend(t, k)

	k.m["tenant_governance.json"] = []byte(`{"stale":true}`)
	k.m[tenantGovernancePath()] = []byte(`{"current":true}`)

	migrateLegacyKVKeys()

	got, _ := kvLoad(tenantGovernancePath())
	if string(got) != `{"current":true}` {
		t.Fatalf("current key = %q, want the live value untouched — the migration "+
			"overwrote live config with a stale legacy row", got)
	}
}

// TestMigrateIsIdempotent: startup runs it every boot.
func TestMigrateIsIdempotent(t *testing.T) {
	k := newMemKV()
	withBackend(t, k)
	k.m["tenant_display.json"] = []byte(`{"t_1":{"time_display":"utc"}}`)

	first := migrateLegacyKVKeys()
	second := migrateLegacyKVKeys()

	if len(first) == 0 {
		t.Fatal("first run recovered nothing")
	}
	if len(second) != 0 {
		t.Fatalf("second run recovered %v — the migration is not idempotent and will "+
			"churn the store on every boot", second)
	}
}

// TestMigrateNoOpsOnFreshInstall: no legacy keys, nothing to do, no noise.
func TestMigrateNoOpsOnFreshInstall(t *testing.T) {
	withBackend(t, newMemKV())
	if got := migrateLegacyKVKeys(); len(got) != 0 {
		t.Fatalf("fresh install recovered %v, want nothing", got)
	}
}

// TestEveryRenamedStoreHasALegacyMapping guards the CLASS: the stores whose
// keys were rewritten by the F-63 fix must each appear in the migration table.
// A store renamed without an entry strands its data silently — which is the
// entire defect this file exists to repair.
func TestEveryRenamedStoreHasALegacyMapping(t *testing.T) {
	renamed := map[string]string{
		"tenant governance": tenantGovernancePath(),
		"tenant display":    tenantDisplayPath(),
		"rca promotions":    rcaPromotionsPath(),
		"rca revisions":     rcaRevisionsPath(),
		"rca action items":  rcaActionItemsPath(),
		"cloud slo":         cloudSLOPath(),
		"cloud monitors":    cloudMonitorsPath(),
	}
	table := legacyKVKeys()
	for name, key := range renamed {
		if _, ok := table[key]; !ok {
			t.Errorf("%s (%s) has no legacy-key mapping — data written under its "+
				"pre-rename key is unreachable and reads as lost", name, key)
		}
	}
}
