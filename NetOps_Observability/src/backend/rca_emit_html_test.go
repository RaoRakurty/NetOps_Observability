package main

import (
	"encoding/json"
	"netops/backend/internal/ticketing"
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
		Policy: ticketing.DefaultIncidentPolicy("t1"), Now: time.Date(2026, 7, 12, 13, 45, 0, 0, time.UTC),
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

// TestEmitRichReportHTML renders a MAXIMAL synthetic report — at-a-glance,
// multi-hop path with a red break + provider boundary + unknown hop, evidence
// summary with per-symptom density, accounting, coverage, cloud changes,
// cascade, ranked hypotheses, ownership candidates, decision, actions — to a
// file for print-layout inspection (the PDF pipeline consumes this HTML
// verbatim). Writes ONLY when RCA_EMIT_HTML_RICH is set; inert in CI.
func TestEmitRichReportHTML(t *testing.T) {
	out := os.Getenv("RCA_EMIT_HTML_RICH")
	if out == "" {
		t.Skip("set RCA_EMIT_HTML_RICH=/path/to/out.html to emit")
	}
	rep := buildRichFixtureReport(t)
	html, err := renderRcaReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if err := os.WriteFile(out, html, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Logf("wrote %d bytes to %s (quality passed=%v, type=%q)", len(html), out, rep.Quality.Passed, rep.ReportType)
}

// buildRichFixtureReport assembles the fully-populated synthetic case the
// rich-emit harness renders. Kept a helper so layout tests can reuse the same
// worst-case document shape.
func buildRichFixtureReport(t *testing.T) rcaReport {
	t.Helper()
	hyps := map[string]any{
		"grounding_context": map[string]any{
			"seams": []any{map[string]any{"seam_id": "dallas-dx-1", "tenant_id": "t1", "seam_type": "IPSEC"}},
		},
		"ranking": map[string]any{"hypotheses": []any{
			map[string]any{
				"id": "sig.ent.cloud.ipsec-tunnel-down", "confidence": 0.62, "confidence_label": "suspected",
				"satisfied": []string{"ipsec_tunnel_status", "probe_loss"}, "missing": []string{"cloud_health"},
				"causal_chain": []any{
					map[string]any{"stage": "IPsec tunnel down (IKE_SA lost)", "witnessed": true, "root": true,
						"note": "IKE/DPD timeout observed on the VPN gateway", "kinds": []string{"ipsec_tunnel_status"}},
					map[string]any{"stage": "Routes via the tunnel withdrawn", "witnessed": false,
						"note": "No routing-protocol signals seen in this window", "kinds": []string{"bgp_adjacency_change"}},
					map[string]any{"stage": "Customer-path packet loss", "witnessed": true,
						"note": "Sustained probe loss from two independent vantages toward 10.60.10.10", "kinds": []string{"probe_loss"}},
					map[string]any{"stage": "Application transactions failing", "witnessed": true,
						"note": "HTTP checks against private-app returned connection timeouts"},
				},
				"verdict": map[string]any{
					"verdict_tier": "suspected", "owner": "cloud_provider",
					"reasons":           []string{"control-plane down event plus multi-vantage probe loss; cloud-side health telemetry absent"},
					"first_steps":       []string{"Check the tunnel's IKE_SA on the VPN gateway", "Review AWS VPN tunnel status in the console"},
					"modality_coverage": []string{"control_plane", "active_probe"},
					"observer_coverage": []string{"gw-1", "lan-vantage-1", "branch-vantage-2"},
				},
			},
			map[string]any{
				"id": "sig.ent.wan-edge.bgp-peer-down", "confidence": 0.31, "confidence_label": "possible",
				"satisfied": []string{"probe_loss"}, "missing": []string{"bgp_adjacency_change"},
				"verdict": map[string]any{
					"verdict_tier": "possible", "owner": "isp",
					"reasons":     []string{"path loss alone is consistent with an upstream carrier fault"},
					"first_steps": []string{"Check BGP session state on wan-edge-r1"},
				},
			},
			map[string]any{
				"id": "sig.ent.app.experience-degraded", "confidence": 0.2, "confidence_label": "possible",
				"satisfied": []string{"probe_loss"}, "contradicted": true,
				"contradictions": []string{"server-side health checks stayed green throughout the window"},
				"verdict":        map[string]any{"verdict_tier": "possible", "owner": "app_team"},
			},
		}},
	}
	blob, err := json.Marshal(hyps)
	if err != nil {
		t.Fatalf("marshal hypotheses: %v", err)
	}
	meta := map[string]any{
		"version": float64(3), "state": "open", "verdict_tier": "suspected",
		"top_hypothesis": "sig.ent.cloud.ipsec-tunnel-down", "top_confidence": 0.62,
		"window_start": "2026-07-12 18:10:00", "window_end": "2026-07-12 18:50:00",
		"hypotheses": string(blob),
		"affected":   `{"services":["private-app"],"apps":["private-app"],"regions":["us-east-1"]}`,
		"app_impact": "{}", "evidence_missing": "[]",
	}
	sigs := []map[string]any{
		sigStatusDown("ipsec_tunnel_status", "2026-07-12 18:12:00", "dallas-dx-1"),
	}
	// two independent vantages, recurring loss across the window → density bars
	for _, ts := range []string{"18:12:30", "18:14:30", "18:16:30", "18:20:30", "18:22:30", "18:28:30", "18:34:30", "18:40:30", "18:46:30"} {
		sigs = append(sigs, sigProbeLoss("2026-07-12 "+ts, "crit", "lan-vantage-1", "10.60.10.10"))
	}
	for _, ts := range []string{"18:13:00", "18:19:00", "18:25:00", "18:31:00", "18:43:00"} {
		sigs = append(sigs, sigProbeLoss("2026-07-12 "+ts, "high", "branch-vantage-2", "10.60.10.10"))
	}
	sigs = append(sigs,
		sigFlowAnomaly("2026-07-12 18:15:00", "high"),
		// device telemetry present for part of the window → partial coverage rows
		testSig("cpu_util", "device_telemetry", "wan-edge-r1", "device", "wan-edge-r1", "info", "2026-07-12 18:16:22", false, nil),
		testSig("cpu_util", "device_telemetry", "wan-edge-r1", "device", "wan-edge-r1", "info", "2026-07-12 18:27:44", false, nil),
		// cloud change events: one attached same-resource, one detached temporal-only
		testSig("cloud_change", "control_plane", "cloudtrail", "cloud_resource", "vpn-conn-0a1b2c", "info", "2026-07-12 18:05:41", true,
			map[string]any{"attrs": `{"provider":"AWS","event_source":"ec2.amazonaws.com","event_name":"ModifyVpnConnection","resource_id":"vpn-conn-0a1b2c","region":"us-east-1","account":"123456789012","actor":"deploy-bot@corp"}`}),
		testSig("cloud_audit", "control_plane", "cloudtrail", "cloud_resource", "sg-9f8e7d", "info", "2026-07-12 18:22:10", false,
			map[string]any{"attrs": `{"provider":"AWS","event_source":"ec2.amazonaws.com","event_name":"AuthorizeSecurityGroupIngress","resource_id":"sg-9f8e7d","region":"us-east-1","account":"123456789012","actor":"ops-admin@corp"}`}),
	)
	rep := buildRcaReport(rcaReportInput{
		ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Meta: meta, Signals: sigs,
		Policy: ticketing.DefaultIncidentPolicy("t1"),
		Now:    time.Date(2026, 7, 12, 19, 0, 0, 0, time.UTC),
	})
	rep.Topology = rcaTopologyView{
		Available: true, VantageID: "lan-vantage-1", ObservedAt: "2026-07-12 18:36:41",
		RelationToIncident: "incident_time",
		Hops: []rcaSpineHopView{
			{Index: 1, Label: "lan-vantage-1", Address: "10.60.1.2", Kind: "vantage", State: "responding"},
			{Index: 2, Label: "core-sw-01", Address: "10.60.1.1", Kind: "lan", State: "responding"},
			{Index: 3, Label: "wan-edge-r1", Address: "203.0.113.9", Kind: "wan", State: "responding"},
			{Index: 4, Label: "correlix-vpn-nat-01", Address: "10.60.1.10", Kind: "cloud", State: "responding",
				Fault: "broken", Boundary: "provider", SeamID: "dallas-dx-1", Provider: "aws"},
			{Index: 5, Label: "", Address: "", Kind: "unknown", State: "unknown"},
			{Index: 6, Label: "private-app", Address: "10.60.10.10", Kind: "service", State: "down"},
		},
		DropPoint: "The last responding hop was correlix-vpn-nat-01 (provider boundary); the destination did not respond beyond this point.",
	}
	return rep
}
