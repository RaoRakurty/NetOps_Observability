package main

// rca_report_test.go — the directive's required cases (docs/design/
// rca-report-overhaul.md) at the builder level: state separation, honest
// times, evidence-coverage semantics, cloud-change qualification, title
// discipline, ownership restraint, and the banned-wording list.

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var rcaTestNow = time.Date(2026, 7, 12, 20, 0, 0, 0, time.UTC)

func testSig(kind, lane, observer, entityType, entityID, sev, ts string, attached bool, extra map[string]any) map[string]any {
	sig := map[string]any{
		"signal_id": "s-" + kind + "-" + ts, "kind": kind, "modality_class": lane,
		"observer_id": observer, "entity_type": entityType, "entity_id": entityID,
		"severity": sev, "ts": ts, "attached": attached,
		"value": float64(0), "baseline": float64(0), "metric_name": "", "attrs": "{}",
		"probe_scope": "", "clear_ts": "",
	}
	for k, v := range extra {
		sig[k] = v
	}
	return sig
}

func testMeta(state, verdict, topHyp string, hyp map[string]any) map[string]any {
	blob := "{}"
	if hyp != nil {
		b, _ := json.Marshal(map[string]any{"ranking": map[string]any{"hypotheses": []any{hyp}}})
		blob = string(b)
	}
	return map[string]any{
		"version": float64(3), "state": state, "verdict_tier": verdict,
		"top_hypothesis": topHyp, "top_confidence": 0.5,
		"window_start": "2026-07-12 18:10:00", "window_end": "2026-07-12 18:30:00",
		"hypotheses": blob, "affected": "{}", "app_impact": "{}", "evidence_missing": "[]",
	}
}

func testHyp(id string, conf float64, label string, satisfied, missing, reasons []string, owner string, contradicted bool) map[string]any {
	return map[string]any{
		"id": id, "confidence": conf, "confidence_label": label,
		"satisfied": satisfied, "missing": missing, "contradicted": contradicted,
		"verdict": map[string]any{
			"verdict_tier": label, "owner": owner, "reasons": reasons,
			"modality_coverage": []string{"active_probe"}, "observer_coverage": []string{"prober"},
			"first_steps": []string{"Check the tunnel's IKE_SA on the VPN gateway"},
		},
	}
}

func buildTestReport(t *testing.T, meta map[string]any, sigs []map[string]any) rcaReport {
	t.Helper()
	return buildRcaReport(rcaReportInput{
		ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Meta: meta, Signals: sigs,
		Policy: defaultIncidentPolicy("t1"), Now: rcaTestNow,
	})
}

// 1. Confirmed root cause → the document may call itself an RCA.
func TestRcaReportConfirmedIsRCA(t *testing.T) {
	meta := testMeta("open", "confirmed", "sig.ent.wan-edge.bgp-peer-down",
		testHyp("sig.ent.wan-edge.bgp-peer-down", 0.9, "confirmed",
			[]string{"bgp_adjacency_change", "probe_loss"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss", "active_probe", "prober", "path", "prober->10.0.0.1", "crit", "2026-07-12 18:12:30", true,
			map[string]any{"probe_scope": "customer_path"}),
	}
	rep := buildTestReport(t, meta, sigs)
	if rep.ReportType != "Root Cause Analysis" {
		t.Fatalf("report type = %q, want Root Cause Analysis", rep.ReportType)
	}
	if rep.States.Analysis != "confirmed" || rep.States.Impact != "confirmed" {
		t.Fatalf("states = %+v", rep.States)
	}
}

// 2. Active-check-only recovered anomaly → Incident Assessment, suspected,
// no root cause claim, telemetry-qualified impact wording.
func TestRcaReportActiveCheckOnlyRecovered(t *testing.T) {
	meta := testMeta("closed", "suspected", "undetermined",
		testHyp("sig.x", 0.4, "suspected", []string{"probe_loss"},
			[]string{"flow_volume_anomaly"}, []string{"single modality class (active_probe); need >=2"}, "netops", false))
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "prober->svc", "high", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss_clear", "active_probe", "prober", "path", "prober->svc", "info", "2026-07-12 18:15:15", false,
			map[string]any{"clear_ts": "2026-07-12 18:15:15"}),
	}
	rep := buildTestReport(t, meta, sigs)
	if rep.ReportType != "Incident Assessment" {
		t.Fatalf("report type = %q", rep.ReportType)
	}
	if rep.States.Analysis != "suspected" || rep.States.Incident != "recovered" {
		t.Fatalf("states = %+v", rep.States)
	}
	if rep.RootCause.Identified {
		t.Fatal("root cause must not be identified")
	}
	if rep.RootCause.Statement != "Root cause has not been identified." {
		t.Fatalf("root cause statement = %q", rep.RootCause.Statement)
	}
	if !rep.Times.RecoveredCaptured || !strings.Contains(rep.Times.RecoveredAt, "18:15:15") {
		t.Fatalf("recovered_at = %+v", rep.Times)
	}
	if rep.Times.DurationBasis != "to_recovery" {
		t.Fatalf("duration basis = %q", rep.Times.DurationBasis)
	}
	// impact telemetry-qualified: no bare "no impact"
	if !strings.Contains(rep.Summary.Management, "within available telemetry coverage") &&
		!strings.Contains(rep.Summary.Management, "could not be assessed") {
		t.Fatalf("management impact wording not telemetry-qualified: %q", rep.Summary.Management)
	}
}

// 3+4. Cloud change: temporal-only vs same-resource, never causal from timing.
func TestRcaReportCloudChangeQualification(t *testing.T) {
	meta := testMeta("open", "suspected", "undetermined",
		testHyp("sig.x", 0.4, "suspected", []string{"probe_loss"}, nil, nil, "netops", false))
	attrs := `{"resource_id":"vpn-conn-1","region":"us-west-2","account":"945714973156","actor":"terraform","event_source":"ec2.amazonaws.com","request_id":"req-1"}`
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "prober->10.60.10.10", "crit", "2026-07-12 18:12:00", true, nil),
		testSig("cloud_change", "control_plane", "cloud:945714973156:us-west-2", "cloud_resource", "vpn-conn-1", "info", "2026-07-12 18:10:38", false,
			map[string]any{"attrs": attrs}),
	}
	rep := buildTestReport(t, meta, sigs)
	if len(rep.CloudChanges) != 1 {
		t.Fatalf("cloud changes = %d, want 1", len(rep.CloudChanges))
	}
	c := rep.CloudChanges[0]
	if c.Relationship != "temporal_only" {
		t.Fatalf("relationship = %q, want temporal_only", c.Relationship)
	}
	if c.DeltaSeconds == nil || *c.DeltaSeconds >= 0 {
		t.Fatalf("delta = %v, want negative (change before onset)", c.DeltaSeconds)
	}
	if strings.Contains(strings.ToLower(rep.Title), "cloud change caused") ||
		strings.Contains(c.Explanation, "caused") {
		t.Fatalf("cloud change wording claims causation: %q", c.Explanation)
	}
	if !strings.Contains(c.Explanation, "temporal proximity") {
		t.Fatalf("explanation must state temporal-only basis: %q", c.Explanation)
	}
	// same resource in scope → same_resource
	meta2 := testMeta("open", "suspected", "undetermined", nil)
	meta2["affected"] = `{"services":["vpn-conn-1"]}`
	rep2 := buildTestReport(t, meta2, sigs)
	if rep2.CloudChanges[0].Relationship != "same_resource" {
		t.Fatalf("relationship = %q, want same_resource", rep2.CloudChanges[0].Relationship)
	}
}

// 5+6. Coverage semantics: absent lane = no_data (never normal/healthy);
// present-but-clean lane = normal with counts.
func TestRcaReportCoverageStates(t *testing.T) {
	meta := testMeta("open", "suspected", "undetermined", nil)
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "p->x", "high", "2026-07-12 18:12:00", true, nil),
		testSig("flow_volume_anomaly", "passive_flow", "exp1", "interface", "if1", "info", "2026-07-12 18:13:00", false, nil),
	}
	rep := buildTestReport(t, meta, sigs)
	byClass := map[string]rcaEvidenceLane{}
	for _, l := range rep.Coverage {
		byClass[l.Class] = l
	}
	if l := byClass["passive_flow"]; l.State != "normal" || l.Observations != 1 {
		t.Fatalf("passive_flow lane = %+v, want normal/1", l)
	}
	if l := byClass["control_plane"]; l.State != "no_data" || l.Availability != "no_data" {
		t.Fatalf("control_plane lane = %+v, want no_data", l)
	}
	if l := byClass["control_plane"]; !strings.Contains(l.Finding, "not evidence of health") {
		t.Fatalf("no_data finding must disclaim health: %q", l.Finding)
	}
	if l := byClass["active_probe"]; l.State != "anomalous" || l.Anomalous != 1 {
		t.Fatalf("active_probe lane = %+v", l)
	}
}

// 7. Missing recovery timestamp → Not captured semantics, duration not fabricated.
func TestRcaReportRecoveryNotCaptured(t *testing.T) {
	meta := testMeta("closed", "suspected", "undetermined", nil)
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "p->x", "high", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss", "active_probe", "prober", "path", "p->x", "high", "2026-07-12 18:14:00", true, nil),
	}
	rep := buildTestReport(t, meta, sigs)
	if rep.Times.RecoveredCaptured || rep.Times.RecoveredAt != "" {
		t.Fatalf("recovered_at must be uncaptured: %+v", rep.Times)
	}
	if rep.Times.DurationBasis != "to_last_observation" {
		t.Fatalf("duration basis = %q — a recovery duration must not be fabricated", rep.Times.DurationBasis)
	}
	// A closed window with ZERO recovery evidence is "no longer observed" —
	// never "recovered" (truthfulness §17: signal aging is not recovery).
	if rep.States.Incident != "no_longer_observed" {
		t.Fatalf("incident = %q, want no_longer_observed", rep.States.Incident)
	}
	if rep.States.Recovery != "not_observed" {
		t.Fatalf("recovery = %q, want not_observed", rep.States.Recovery)
	}
	if strings.Contains(rep.Title, "recovered") {
		t.Fatalf("title %q must not claim recovery", rep.Title)
	}
	if !strings.Contains(rep.Summary.Management, "recovery is NOT confirmed") {
		t.Fatalf("management summary must state recovery is not confirmed: %s", rep.Summary.Management)
	}
	// NOC quick-read renders the explicit non-confirmation
	found := false
	for _, kv := range rep.Summary.Noc {
		if kv.K == "Recovered at" && strings.HasPrefix(kv.V, "Not confirmed") {
			found = true
		}
	}
	if !found {
		t.Fatal("NOC quick-read must state recovery is not confirmed")
	}
}

// 7b. A closed window WITH clear evidence is genuinely recovered, and the
// monitoring state is evaluated against report-generation time.
func TestRcaReportRecoveredWithEvidenceAndMonitoringCompleted(t *testing.T) {
	meta := testMeta("closed", "suspected", "undetermined", nil)
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "p->x", "high", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss_clear", "active_probe", "prober", "path", "p->x", "info", "2026-07-12 18:20:00", true, nil),
	}
	rep := buildTestReport(t, meta, sigs) // buildTestReport's Now is far after 18:20
	if rep.States.Incident != "recovered" || rep.States.Recovery != "explicitly_confirmed" {
		t.Fatalf("want recovered/explicitly_confirmed, got %s/%s", rep.States.Incident, rep.States.Recovery)
	}
	if rep.States.Monitoring != "completed" {
		t.Fatalf("monitoring = %q — a window that ended before generation must read completed", rep.States.Monitoring)
	}
}

// 8. Active incident → elapsed duration, no recovered state.
func TestRcaReportActiveElapsed(t *testing.T) {
	meta := testMeta("open", "suspected", "undetermined", nil)
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "p->x", "crit", "2026-07-12 19:50:00", true, nil),
	}
	rep := buildTestReport(t, meta, sigs)
	if rep.States.Incident != "active" {
		t.Fatalf("incident = %q", rep.States.Incident)
	}
	if rep.Times.DurationBasis != "elapsed_still_active" || rep.Times.DurationMS != int64(10*time.Minute/time.Millisecond) {
		t.Fatalf("times = %+v", rep.Times)
	}
}

// 9. No service name → the title falls back to the target, never to
// "Network change observed".
func TestRcaReportTitleFallbackNoService(t *testing.T) {
	meta := testMeta("closed", "suspected", "undetermined", nil)
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "prober->10.61.10.10", "high", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss_clear", "active_probe", "prober", "path", "prober->10.61.10.10", "info", "2026-07-12 18:15:00", false,
			map[string]any{"clear_ts": "2026-07-12 18:15:00"}),
	}
	rep := buildTestReport(t, meta, sigs)
	if strings.Contains(rep.Title, "Network change") {
		t.Fatalf("title %q uses the banned generic fallback", rep.Title)
	}
	if !strings.Contains(rep.Title, "active-check degradation") || !strings.Contains(rep.Title, "recovered") {
		t.Fatalf("title = %q, want evidence-based transient active-check title", rep.Title)
	}
}

// 10. Owner restraint: unconfirmed app-endpoint case keeps triage at NOC and
// does not assert an app-team escalation owner.
func TestRcaReportOwnerRestraint(t *testing.T) {
	meta := testMeta("open", "suspected", "undetermined",
		testHyp("sig.ent.app.something", 0.4, "suspected", []string{"probe_loss"}, nil, nil, "app_team", false))
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "p->app", "high", "2026-07-12 18:12:00", true, nil),
	}
	rep := buildTestReport(t, meta, sigs)
	if rep.Ownership.TriageOwner != "NOC" {
		t.Fatalf("triage owner = %q", rep.Ownership.TriageOwner)
	}
	if rep.Ownership.EscalationOwner == "Application team" {
		t.Fatal("suspected-only evidence must not assert an app-team escalation owner")
	}
	if rep.Ownership.SuspectedDomain != "Undetermined" {
		t.Fatalf("suspected domain = %q, want Undetermined at suspected", rep.Ownership.SuspectedDomain)
	}
	// candidates may NAME the team, with the hypothesis as the stated basis
	if len(rep.Ownership.Candidates) == 0 || rep.Ownership.Candidates[0].Reason == "" {
		t.Fatalf("candidates must carry reasons: %+v", rep.Ownership.Candidates)
	}
}

// 11+14. No filler hypotheses; historical objects with empty blobs render
// without panic and with explicit unknown states.
func TestRcaReportNoFillerAndHistoricalCompat(t *testing.T) {
	meta := testMeta("open", "undetermined", "undetermined", nil)
	rep := buildTestReport(t, meta, nil)
	if len(rep.Hypotheses) != 0 || !rep.SingleHypothesis {
		t.Fatalf("empty evidence must not invent hypotheses: %+v", rep.Hypotheses)
	}
	if rep.States.Analysis != "observed" || rep.States.Impact != "not_observable" {
		t.Fatalf("states = %+v", rep.States)
	}
	if rep.States.Severity != "unknown" {
		t.Fatalf("severity = %q, want unknown (not fabricated)", rep.States.Severity)
	}
}

// 13/15. Rendered HTML: controlled document, no browser artifacts, no banned
// wording, both layers present.
func TestRcaReportHTMLGolden(t *testing.T) {
	meta := testMeta("closed", "suspected", "undetermined",
		testHyp("sig.ent.cloud.ipsec-tunnel-down", 0.5, "suspected",
			[]string{"ipsec_tunnel_status"}, []string{"probe_loss|cloud_health"},
			[]string{"single observer (ipsec:lab-vpn-edge); need >=2"}, "netops", false))
	sigs := []map[string]any{
		testSig("ipsec_tunnel_status", "control_plane", "ipsec:gw", "cloud_resource", "sm-1", "crit", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss_clear", "control_plane", "ipsec:gw", "cloud_resource", "sm-1", "info", "2026-07-12 18:20:00", false,
			map[string]any{"clear_ts": "2026-07-12 18:20:00"}),
	}
	rep := buildTestReport(t, meta, sigs)
	html, err := renderRcaReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	for _, banned := range []string{
		"about:blank", "Network change observed", "No signals seen",
		"matches this issue type", "evidence changed", "real network issue",
	} {
		if strings.Contains(doc, banned) {
			t.Fatalf("rendered report contains banned string %q", banned)
		}
	}
	for _, want := range []string{
		"Management summary", "NOC quick read", "Evidence coverage",
		"Root cause has not been identified", "Incident Assessment",
		"IKE/DPD", // the ipsec problem statement names the actual suspect
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("rendered report missing %q", want)
		}
	}
}

// The four state dimensions stay independent: a recovered incident never
// upgrades the analysis, and "Recovered" never appears as the analysis state.
func TestRcaReportStateIndependence(t *testing.T) {
	meta := testMeta("closed", "suspected", "undetermined", nil)
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "p->x", "high", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss_clear", "active_probe", "prober", "path", "p->x", "info", "2026-07-12 18:15:00", false,
			map[string]any{"clear_ts": "2026-07-12 18:15:00"}),
	}
	rep := buildTestReport(t, meta, sigs)
	if rep.States.Incident != "recovered" {
		t.Fatalf("incident = %q", rep.States.Incident)
	}
	if rep.States.Analysis == "recovered" || rep.States.Analysis == "confirmed" {
		t.Fatalf("analysis = %q — lifecycle leaked into analysis", rep.States.Analysis)
	}
}

// 12. Tenant scoping: the endpoint refuses an unauthenticated request BEFORE
// any data read (the dispatch layer additionally gates on requirePerm, and the
// slice reads run under chTenantScope + ClickHouse row policies).
func TestRcaReportEndpointRequiresPrincipal(t *testing.T) {
	s := &server{}
	r := httptest.NewRequest("GET", "/api/correlations/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/rca-report", nil)
	w := httptest.NewRecorder()
	s.serveRcaReport(w, r, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	if w.Code != 401 {
		t.Fatalf("unauthenticated rca-report = %d, want 401", w.Code)
	}
}

// 7c. Semantic up-state events are recovery evidence (§17) — but only when
// observed AFTER the first anomaly; a pre-fault healthy assertion is not.
func TestRcaReportSemanticUpIsRecoveryEvidence(t *testing.T) {
	meta := testMeta("closed", "suspected", "undetermined", nil)
	up := func(ts string) map[string]any {
		return testSig("ipsec_tunnel_status", "control_plane", "ipsec:gw", "seam", "sm-1", "info",
			ts, false, map[string]any{"attrs": `{"state":"up"}`})
	}
	down := testSig("ipsec_tunnel_status", "control_plane", "ipsec:gw", "seam", "sm-1", "crit",
		"2026-07-12 18:10:00", true, map[string]any{"attrs": `{"state":"down"}`})

	// pre-fault up ONLY → no recovery claim
	rep := buildTestReport(t, meta, []map[string]any{up("2026-07-12 18:00:00"), down})
	if rep.States.Recovery != "not_observed" || rep.States.Incident != "no_longer_observed" {
		t.Fatalf("pre-fault up must not prove recovery: %s/%s", rep.States.Incident, rep.States.Recovery)
	}

	// post-fault up → genuine recovery, timestamped from the up event
	rep = buildTestReport(t, meta, []map[string]any{down, up("2026-07-12 18:30:00")})
	if rep.States.Incident != "recovered" || rep.States.Recovery != "explicitly_confirmed" {
		t.Fatalf("post-fault up must prove recovery: %s/%s", rep.States.Incident, rep.States.Recovery)
	}
	if rep.Times.RecoveredAt != "2026-07-12 18:30:00 UTC" {
		t.Fatalf("recovered_at = %q, want the up event's time", rep.Times.RecoveredAt)
	}
}
