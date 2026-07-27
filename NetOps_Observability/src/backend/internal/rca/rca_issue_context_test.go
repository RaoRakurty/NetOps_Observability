package rca

// rca_issue_context_test.go — unit tests for the IssueContextResolver
// (rca_issue_context.go). The scenario suite proves the consolidation changed
// no behavior; these tests pin the resolver's own field derivations.

import (
	"encoding/json"
	"strings"
	"testing"
)

func testHypBlob(t *testing.T, hyp map[string]any) rcaHypBlob {
	t.Helper()
	b, err := json.Marshal(map[string]any{"ranking": map[string]any{"hypotheses": []any{hyp}}})
	if err != nil {
		t.Fatal(err)
	}
	var hb rcaHypBlob
	if err := json.Unmarshal(b, &hb); err != nil {
		t.Fatal(err)
	}
	return hb
}

func TestResolveIssueContextIpsecCase(t *testing.T) {
	hyp := testHyp("sig.ent.cloud.ipsec-tunnel-down", 0.9, "confirmed",
		[]string{"ipsec_tunnel_status"}, []string{"probe_loss"}, nil, "netops", false)
	ctx := resolveIssueContext(rcaIssueContextInput{
		Analysis: "confirmed", RecoveryState: "not_observed", ImpactRU: "not_observable",
		Hyp:     testHypBlob(t, hyp),
		Targets: []string{"10.60.10.10"},
		LaneAnomalous: map[string]int{
			"control_plane": 1, "active_probe": 2,
		},
		KindCounts: map[string]int{"ipsec_tunnel_status": 1, "probe_loss": 2},
		Anomalous: []map[string]any{
			testSig("probe_loss", "active_probe", "v1", "path", "v1->10.60.10.10", "crit", "2026-07-12 18:00:00", true,
				map[string]any{"probe_scope": "customer_path"}),
		},
	})
	if ctx.IssueFamily != "cloud" {
		t.Fatalf("issue family = %q", ctx.IssueFamily)
	}
	if ctx.ServiceClassification != "customer-managed internal application" {
		t.Fatalf("service classification = %q", ctx.ServiceClassification)
	}
	if ctx.PathType != "customer_path" {
		t.Fatalf("path type = %q", ctx.PathType)
	}
	if ctx.Environment != "production" {
		t.Fatalf("environment = %q", ctx.Environment)
	}
	if got := strings.Join(ctx.ParticipatingModalities, ","); got != "control_plane,active_probe" {
		t.Fatalf("modalities = %q", got)
	}
	// ipsec + path families participated; bgp/dns did not
	if !ctx.familyApplicable("ipsec") || !ctx.familyApplicable("path") {
		t.Fatalf("applicable = %v", ctx.ApplicableActions)
	}
	if ctx.familyApplicable("bgp") || ctx.familyApplicable("dns") {
		t.Fatalf("absent families marked applicable: %v", ctx.ApplicableActions)
	}
	// active failure stage from the probe evidence
	if ctx.ActiveFailureStage != "Packet loss" {
		t.Fatalf("failure stage = %q", ctx.ActiveFailureStage)
	}
	// confirmation gates humanized from the missing clauses
	if len(ctx.RequiredConfirmationGates) == 0 {
		t.Fatal("missing-clause gates not surfaced")
	}
	// prohibited claims: root cause always; recovery + impact by state
	joined := strings.Join(ctx.ProhibitedClaims, ",")
	for _, want := range []string{"root_cause_identified", "recovery_claim", "customer_impact_confirmed", "no_customer_impact"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("prohibited claims missing %q: %v", want, ctx.ProhibitedClaims)
		}
	}
	if ctx.topIsSymptom { // causal hypothesis, not a symptom
		t.Fatal("ipsec hypothesis misclassified as symptom")
	}
}

func TestResolveIssueContextFlowOnlySymptom(t *testing.T) {
	hyp := testHyp("sig.ent.app.saas-experience-degraded", 0.4, "suspected",
		[]string{"flow_volume_anomaly"}, nil, nil, "app_team", false)
	ctx := resolveIssueContext(rcaIssueContextInput{
		Analysis: "suspected", RecoveryState: "inferred", ImpactRU: "indicator_detected",
		Hyp:           testHypBlob(t, hyp),
		LaneAnomalous: map[string]int{"passive_flow": 1},
		KindCounts:    map[string]int{"flow_volume_anomaly": 1},
	})
	if ctx.IssueFamily != "app" {
		t.Fatalf("issue family = %q", ctx.IssueFamily)
	}
	if !ctx.topIsSymptom {
		t.Fatal("experience signature must resolve as symptom classification")
	}
	if !ctx.familyApplicable("flow") {
		t.Fatal("flow family must be applicable")
	}
	if ctx.familyApplicable("ipsec") {
		t.Fatal("ipsec family must not be applicable on a flow-only case")
	}
	if ctx.PathType != "" {
		t.Fatalf("path type = %q, want empty (no probe evidence)", ctx.PathType)
	}
}

func TestResolveIssueContextNoSignatureAndValidation(t *testing.T) {
	// no signature → dominant anomalous lane names the family factually
	ctx := resolveIssueContext(rcaIssueContextInput{
		Analysis: "observed", RecoveryState: "not_observed", ImpactRU: "not_observable",
		Validation:    true,
		LaneAnomalous: map[string]int{"device_telemetry": 3, "active_probe": 1},
		KindCounts:    map[string]int{"cpu_high": 3, "probe_loss": 1},
	})
	if ctx.IssueFamily != "device_telemetry" {
		t.Fatalf("issue family = %q", ctx.IssueFamily)
	}
	if ctx.Environment != "validation" {
		t.Fatalf("environment = %q", ctx.Environment)
	}
	found := false
	for _, c := range ctx.ProhibitedClaims {
		if c == "production_severity" {
			found = true
		}
	}
	if !found {
		t.Fatalf("validation must prohibit production severity: %v", ctx.ProhibitedClaims)
	}
	// external accountability prohibition appears only with an external top owner
	for _, c := range ctx.ProhibitedClaims {
		if c == "external_provider_accountability_without_demarcation" {
			t.Fatalf("external prohibition without external owner: %v", ctx.ProhibitedClaims)
		}
	}
}

// assessDemarcation — the P1.10 promotion contract: provider-side alarm AND
// independent-vantage evidence, with provider-scoped alarm kinds.
func TestAssessDemarcation(t *testing.T) {
	cases := []struct {
		name  string
		team  string
		kinds map[string]int
		want  string
	}{
		{"alarm + vantage promotes carrier", "ISP / carrier",
			map[string]int{"provider_alarm": 1, "independent_vantage_probe": 1, "probe_loss": 2},
			"provider_boundary_confirmed"},
		{"carrier alarm kind promotes too", "Carrier",
			map[string]int{"carrier_alarm": 1, "independent_vantage_probe": 1},
			"provider_boundary_confirmed"},
		{"cloud health speaks only for the cloud provider", "ISP / carrier",
			map[string]int{"cloud_health": 1, "independent_vantage_probe": 1},
			"local_checks_pending"},
		{"cloud health + vantage promotes cloud provider", "Cloud provider",
			map[string]int{"cloud_health": 1, "independent_vantage_probe": 1},
			"provider_boundary_confirmed"},
		{"alarm alone stays pending", "ISP / carrier",
			map[string]int{"provider_alarm": 1, "probe_loss": 3},
			"local_checks_pending"},
		{"vantage alone stays pending", "ISP / carrier",
			map[string]int{"independent_vantage_probe": 1, "probe_loss": 3},
			"local_checks_pending"},
		{"no evidence stays pending", "ISP / carrier",
			map[string]int{"probe_loss": 3},
			"local_checks_pending"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state, basis := assessDemarcation(tc.team, tc.kinds)
			if state != tc.want {
				t.Fatalf("state = %q, want %q (basis %q)", state, tc.want, basis)
			}
			if basis == "" {
				t.Fatal("basis must always be stated")
			}
		})
	}
}
