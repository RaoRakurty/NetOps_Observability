package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestSNMPProfileStoreSeedAndExtend(t *testing.T) {
	s, err := newSNMPProfileStore(t.TempDir() + "/p.json")
	if err != nil {
		t.Fatal(err)
	}
	// Built-ins are seeded.
	if len(s.List()) < 8 {
		t.Fatalf("expected built-in profiles, got %d", len(s.List()))
	}
	cisco, ok := s.Get("cisco-ios")
	if !ok || len(cisco.Metrics) == 0 || !cisco.Builtin {
		t.Fatal("cisco-ios built-in profile missing/empty")
	}
	// F5 BIG-IP built-in (#94 vendor profiles): std port floor + LB/trunk OIDs.
	f5, ok := s.Get("f5-bigip")
	if !ok || !f5.Builtin || f5.Category != "load_balancer" || len(f5.Metrics) == 0 {
		t.Fatalf("f5-bigip built-in profile missing/wrong: %+v (ok=%v)", f5, ok)
	}

	// Add a custom metric; duplicate OID is skipped.
	before := len(cisco.Metrics)
	got, err := s.AddMetrics("cisco-ios", []SNMPMetric{
		{Name: "customLoad", OID: "1.3.6.1.4.1.9.2.1.58.0", Type: "gauge", Unit: "%"},
		{Name: "dupe", OID: cisco.Metrics[0].OID}, // duplicate → skipped
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Metrics) != before+1 {
		t.Errorf("AddMetrics: got %d metrics, want %d", len(got.Metrics), before+1)
	}

	// Built-ins cannot be deleted; custom profiles can.
	if err := s.Delete("cisco-ios"); err == nil {
		t.Error("deleting a built-in profile should fail")
	}
	if _, err := s.Upsert(SNMPProfile{Vendor: "ACME NetGear", Category: "router_switch",
		Metrics: []SNMPMetric{{Name: "x", OID: "1.2.3.4", Type: "gauge"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("acme-netgear"); err != nil {
		t.Errorf("deleting a custom profile should succeed: %v", err)
	}
}

// TestSNMPProfileStoreLegacyMigration proves the source-authoritative model:
// a legacy bare-array store containing (a) an orphaned built-in whose source was
// removed, and (b) a contaminated built-in (a real source id carrying an extra
// stale metric) is purged on load, while operator-authored custom profiles are
// preserved. This is the regression guard for the "deleted Datadog profiles
// still show up" bug.
func TestSNMPProfileStoreLegacyMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snmp_profiles.json")

	// A real built-in id to confirm it survives in source form (not the persisted shape).
	realID := builtinSNMPProfiles()[0].ID

	legacy := []SNMPProfile{
		// (a) orphaned built-in — no longer defined in source. Must be purged.
		{ID: "western-digital-mycloud-ex2-ultra", Vendor: "WD MyCloud", Category: "storage",
			Builtin: true, Metrics: []SNMPMetric{{Name: "x", OID: "1.2.3.4", Type: "gauge"}}},
		// (b) contaminated built-in — a source id carrying a stale extra metric. The
		//     stale metric must NOT survive (built-in rebuilt from source).
		{ID: realID, Vendor: "stale", Category: "stale", Builtin: true,
			Metrics: []SNMPMetric{{Name: "staleMetric", OID: "9.9.9.9.9", Type: "gauge"}}},
		// (c) operator-authored custom profile — must be preserved verbatim.
		{ID: "acme-custom", Vendor: "ACME Custom", Category: "router_switch", Builtin: false,
			Metrics: []SNMPMetric{{Name: "acme", OID: "1.3.6.1.4.1.99999.1", Type: "gauge"}}},
	}
	b, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := newSNMPProfileStore(path)
	if err != nil {
		t.Fatal(err)
	}

	// (a) orphaned built-in gone.
	if _, ok := s.Get("western-digital-mycloud-ex2-ultra"); ok {
		t.Error("orphaned built-in survived migration — should be purged")
	}
	// (b) real built-in present, rebuilt from source, stale metric gone.
	rp, ok := s.Get(realID)
	if !ok || !rp.Builtin {
		t.Fatalf("source built-in %q missing after migration", realID)
	}
	for _, m := range rp.Metrics {
		if m.OID == "9.9.9.9.9" {
			t.Error("stale metric on built-in survived — built-in not rebuilt from source")
		}
	}
	// (c) custom profile preserved.
	cp, ok := s.Get("acme-custom")
	if !ok || cp.Builtin || len(cp.Metrics) != 1 {
		t.Errorf("custom profile not preserved across migration: %+v (ok=%v)", cp, ok)
	}

	// The store is now re-persisted as an operator-intent-only JSON array: no
	// built-in base definition should appear on disk (PG explodes this by "id").
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted []SNMPProfile
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("persisted store is not a JSON array (PG explode needs an array): %v", err)
	}
	for _, p := range persisted {
		if p.Builtin {
			t.Errorf("built-in %q persisted to disk — must be source-only", p.ID)
		}
	}

	// Operator overlay on a built-in survives a reload (the extend-a-built-in feature).
	if _, err := s.AddMetrics(realID, []SNMPMetric{
		{Name: "opAdded", OID: "1.3.6.1.4.1.42.42.42", Type: "gauge"}}); err != nil {
		t.Fatal(err)
	}
	s2, err := newSNMPProfileStore(path) // simulate reboot
	if err != nil {
		t.Fatal(err)
	}
	rp2, _ := s2.Get(realID)
	found := false
	for _, m := range rp2.Metrics {
		if m.OID == "1.3.6.1.4.1.42.42.42" {
			found = true
		}
	}
	if !found {
		t.Error("operator overlay metric did not survive reload")
	}
}

func TestSNMPProfilesEndpoint(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st, b := do(t, srv, "GET", "/api/snmp/profiles", admin, nil)
	if st != 200 {
		t.Fatalf("list profiles: %d", st)
	}
	var profiles []SNMPProfile
	if err := json.Unmarshal(b, &profiles); err != nil {
		t.Fatal(err)
	}
	if len(profiles) == 0 {
		t.Fatal("expected built-in profiles from the endpoint")
	}

	// Add a metric via the API.
	st, _ = do(t, srv, "POST", "/api/snmp/profiles/ups/metrics", admin,
		[]map[string]any{{"name": "upsInputVoltage", "oid": "1.3.6.1.2.1.33.1.3.1.3", "type": "gauge", "unit": "V"}})
	if st != http.StatusOK {
		t.Fatalf("add metric: %d", st)
	}
}
