package main

import (
	"encoding/json"
	"net/http"
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
