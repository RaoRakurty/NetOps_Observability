// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

import (
	"testing"
)

// (Test 7/8) a lane that observed cleanly but did NOT span the full incident
// window is PARTIAL / inconclusive — never a green Normal — and states its
// missing interval (P1 evidence-coverage quality). Generic across any lane.
func TestEvidenceCoveragePartialNotNormal(t *testing.T) {
	meta := testMeta("open", "confirmed", "sig.ent.cloud.ipsec-tunnel-down",
		testHyp("sig.ent.cloud.ipsec-tunnel-down", 0.9, "confirmed",
			[]string{"probe_loss"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		// anomalous probe spans the incident window 18:10 → 18:25
		testSig("probe_loss", "active_probe", "prober", "path", "prober->10.60.10.10", "crit",
			"2026-07-12 18:10:00", true, map[string]any{"probe_scope": "customer_path"}),
		testSig("probe_loss", "active_probe", "prober", "path", "prober->10.60.10.10", "crit",
			"2026-07-12 18:25:00", true, map[string]any{"probe_scope": "customer_path"}),
		// device-health telemetry present but stops at 18:15 — before the last anomaly
		testSig("cpu_util", "device_telemetry", "dev-1", "device", "dev-1", "info",
			"2026-07-12 18:10:00", false, nil),
		testSig("cpu_util", "device_telemetry", "dev-1", "device", "dev-1", "info",
			"2026-07-12 18:15:00", false, nil),
	}
	rep := buildTestReport(t, meta, sigs)

	var dev *rcaEvidenceLane
	for i := range rep.Coverage {
		if rep.Coverage[i].Class == "device_telemetry" {
			dev = &rep.Coverage[i]
		}
	}
	if dev == nil {
		t.Fatal("device_telemetry lane missing from coverage")
	}
	if dev.State == "normal" {
		t.Fatalf("partial-coverage lane must not read green Normal: %+v", dev)
	}
	if dev.State != "inconclusive" || dev.Coverage != "partial" {
		t.Fatalf("device lane state=%q coverage=%q, want inconclusive/partial", dev.State, dev.Coverage)
	}
	if dev.MissingInterval == "" {
		t.Fatal("partial coverage must state its missing interval")
	}
}
