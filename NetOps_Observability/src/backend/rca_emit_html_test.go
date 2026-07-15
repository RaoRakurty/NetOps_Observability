package main

import (
	"os"
	"testing"
	"time"
)

// TestEmitMergedReportHTML renders a merged incident report to HTML for visual
// inspection. It writes ONLY when RCA_EMIT_HTML is set, so it is inert in CI.
// The fact-set is P-E22C5E-SHAPED but fully synthetic and generic (component
// recovery + residual + merge), not a case-specific fixture.
func TestEmitMergedReportHTML(t *testing.T) {
	out := os.Getenv("RCA_EMIT_HTML")
	if out == "" {
		t.Skip("set RCA_EMIT_HTML=/path/to/out.html to emit")
	}
	meta := testMeta("merged", "confirmed", "sig.ent.cloud.ipsec-tunnel-down",
		testHyp("sig.ent.cloud.ipsec-tunnel-down", 0.92, "confirmed",
			[]string{"ipsec_tunnel_status", "probe_loss"}, nil, nil, "netops", false))
	meta["merged_into"] = "11112222-3333-4444-5555-666677778888"
	meta["affected"] = `{"services":["private-app"],"apps":["private-app"]}`
	sigs := []map[string]any{
		sigStatusDown("ipsec_tunnel_status", "2026-07-12 13:24:21", "lab-vpn-edge"),
		sigProbeLoss("2026-07-12 13:24:21", "crit", "lan-vantage-1", "10.60.10.10"),
		sigProbeLoss("2026-07-12 13:29:00", "crit", "lan-vantage-1", "10.60.10.10"),
		sigStatusUp("ipsec_tunnel_status", "2026-07-12 13:29:58", "lab-vpn-edge"),
		sigProbeLoss("2026-07-12 13:34:49", "crit", "lan-vantage-1", "10.60.10.10"),
		sigProbeLoss("2026-07-12 13:39:00", "crit", "lan-vantage-1", "10.60.10.10"),
		// device-health telemetry that stops before the last anomaly → partial
		testSig("cpu_util", "device_telemetry", "dev-1", "device", "dev-1", "info", "2026-07-12 13:26:22", false, nil),
		testSig("cpu_util", "device_telemetry", "dev-1", "device", "dev-1", "info", "2026-07-12 13:37:44", false, nil),
	}
	rep := buildRcaReport(rcaReportInput{
		ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Meta: meta, Signals: sigs,
		Policy: defaultIncidentPolicy("t1"), Now: time.Date(2026, 7, 12, 13, 45, 0, 0, time.UTC),
		SurvivingIncidentID: "11112222-3333-4444-5555-666677778888",
	})
	// attach a responding-hop path to exercise the boundary rendering
	rep.Topology = rcaTopologyView{
		Available: true, VantageID: "lan-vantage-1", ObservedAt: "2026-07-12 13:36:41",
		RelationToIncident: "incident_time",
		Hops: []rcaSpineHopView{
			{Index: 1, Label: "lan-vantage-1", Address: "10.60.1.2", Kind: "vantage", State: "responding"},
			{Index: 2, Label: "correlix-vpn-nat-01", Address: "10.60.1.10", Kind: "cloud", State: "responding", Fault: "broken", Boundary: "provider", Provider: "aws"},
			{Index: 3, Label: "", Address: "", Kind: "unknown", State: "unknown"},
		},
		DropPoint: "The last responding hop was correlix-vpn-nat-01; the destination did not respond beyond this point.",
	}
	html, err := renderRcaReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if err := os.WriteFile(out, html, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Logf("wrote %d bytes to %s (quality passed=%v, type=%q)", len(html), out, rep.Quality.Passed, rep.ReportType)
}
