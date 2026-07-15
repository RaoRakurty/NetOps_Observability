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

// 1. A confirmed signature verdict confirms the FAULT CONDITION — never the
// root cause (P1.3). The document is a fault-confirmed incident analysis; it
// may call itself an RCA only when mechanism + causal object concluded.
func TestRcaReportConfirmedIsFaultConfirmedNotRCA(t *testing.T) {
	meta := testMeta("open", "confirmed", "sig.ent.wan-edge.bgp-peer-down",
		testHyp("sig.ent.wan-edge.bgp-peer-down", 0.9, "confirmed",
			[]string{"bgp_adjacency_change", "probe_loss"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss", "active_probe", "prober", "path", "prober->10.0.0.1", "crit", "2026-07-12 18:12:30", true,
			map[string]any{"probe_scope": "customer_path"}),
	}
	rep := buildTestReport(t, meta, sigs)
	if rep.ReportType != "Incident Analysis — Fault Confirmed" {
		t.Fatalf("report type = %q, want Incident Analysis — Fault Confirmed", rep.ReportType)
	}
	if rep.States.Analysis != "confirmed" || rep.States.FaultDomain != "confirmed" {
		t.Fatalf("states = %+v", rep.States)
	}
	// synthetic evidence only → impact is detected (synthetic scope), never
	// "confirmed" customer impact; root cause stays under investigation.
	if rep.States.Impact != "detected" || rep.States.ImpactSynthetic != "confirmed" {
		t.Fatalf("impact = %s / syn %s", rep.States.Impact, rep.States.ImpactSynthetic)
	}
	if rep.States.RootCauseState != "under_investigation" || rep.RootCause.Identified {
		t.Fatalf("root cause = %s identified=%v — a verdict never confirms root cause",
			rep.States.RootCauseState, rep.RootCause.Identified)
	}
	if !rep.Quality.Passed {
		t.Fatalf("quality gate failed: %+v", rep.Quality.Errors)
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
	// impact telemetry-qualified: no bare "no impact" — synthetic-only evidence
	// states the synthetic scope and the unconfirmed real-user axis explicitly.
	// (P1.6: a single covering axis is PARTIAL coverage — the overall no-impact
	// claim is not made; the covered axis is reported honestly instead.)
	if !strings.Contains(rep.Summary.Management, "Synthetic path impact is confirmed") &&
		!strings.Contains(rep.Summary.Management, "coverage was incomplete") &&
		!strings.Contains(rep.Summary.Management, "could not be assessed") {
		t.Fatalf("management impact wording not telemetry-qualified: %q", rep.Summary.Management)
	}
	if rep.States.Impact == "none_detected" {
		t.Fatal("single-axis coverage must not ground a no-impact claim (P1.6)")
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
	if rep.States.Recovery != "inferred" {
		t.Fatalf("recovery = %q, want inferred (ended only by time)", rep.States.Recovery)
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
	if rep.States.Monitoring != "completed_no_recurrence" {
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
	if rep.States.Recovery != "inferred" || rep.States.Incident != "no_longer_observed" {
		t.Fatalf("pre-fault up must not prove EXPLICIT recovery: %s/%s", rep.States.Incident, rep.States.Recovery)
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

// §5: impact axes — synthetic-only confirmation never claims real-user impact.
func TestRcaReportImpactAxes(t *testing.T) {
	meta := testMeta("open", "confirmed", "sig.ent.cloud.ipsec-tunnel-down",
		testHyp("sig.ent.cloud.ipsec-tunnel-down", 0.9, "confirmed",
			[]string{"ipsec_tunnel_status", "probe_loss"}, nil, nil, "netops", false))
	syntheticOnly := []map[string]any{
		testSig("ipsec_tunnel_status", "control_plane", "ipsec:gw", "seam", "sm-1", "crit", "2026-07-12 18:12:00", true,
			map[string]any{"attrs": `{"state":"down"}`}),
		testSig("probe_loss", "active_probe", "prober", "path", "p->10.60.10.10", "crit", "2026-07-12 18:12:30", true,
			map[string]any{"probe_scope": "customer_path"}),
	}
	rep := buildTestReport(t, meta, syntheticOnly)
	// synthetic-only impact never claims customer impact confirmation (P1.5)
	if rep.States.Impact != "detected" || rep.States.ImpactSynthetic != "confirmed" {
		t.Fatalf("synthetic axis wrong: impact=%s syn=%s", rep.States.Impact, rep.States.ImpactSynthetic)
	}
	if rep.States.ImpactRealUser != "not_observable" {
		t.Fatalf("real-user axis = %q — no real-traffic telemetry existed", rep.States.ImpactRealUser)
	}
	if !strings.Contains(rep.Summary.Management, "Synthetic path impact is confirmed") {
		t.Fatalf("summary must qualify synthetic-only impact: %s", rep.Summary.Management)
	}

	// a flow-volume delta is an INDICATOR, never real-user confirmation (P1.5)
	withFlow := append(append([]map[string]any{}, syntheticOnly...),
		testSig("flow_volume_anomaly", "passive_flow", "exporter1", "interface", "if1", "high", "2026-07-12 18:13:00", true, nil))
	rep2 := buildTestReport(t, meta, withFlow)
	if rep2.States.ImpactRealUser != "indicator_detected" {
		t.Fatalf("real-user axis = %q with flow evidence — a volume delta is an indicator", rep2.States.ImpactRealUser)
	}

	// REAL serving-infrastructure errors (LB 5xx) + confirmed analysis → confirmed
	withLB := append(append([]map[string]any{}, syntheticOnly...),
		testSig("lb_5xx", "device_telemetry", "alb-1", "app", "portal", "high", "2026-07-12 18:13:10", true, nil))
	rep3 := buildTestReport(t, meta, withLB)
	if rep3.States.ImpactRealUser != "confirmed" || rep3.States.Impact != "confirmed" {
		t.Fatalf("real-user axis = %s impact = %s with LB error evidence", rep3.States.ImpactRealUser, rep3.States.Impact)
	}
	if !strings.Contains(rep3.Summary.Management, "including real user traffic") {
		t.Fatalf("summary must cite real traffic: %s", rep3.Summary.Management)
	}
}

// §9/§19/§20: single-observation duration honesty, severity basis, ownership
// restraint when the fault is not localized.
func TestRcaReportSingleObservationSeverityAndOwnership(t *testing.T) {
	meta := testMeta("closed", "confirmed", "sig.ent.app.saas-experience-degraded",
		testHyp("sig.ent.app.saas-experience-degraded", 1.0, "confirmed",
			[]string{"synthetic_http_5xx"}, nil, nil, "app_team", false))
	sigs := []map[string]any{
		testSig("synthetic_http_5xx", "active_probe", "canary", "app", "rca_canary_app", "high",
			"2026-07-12 18:12:00", true, map[string]any{"probe_scope": "customer_path"}),
	}
	rep := buildTestReport(t, meta, sigs)
	if rep.Times.DurationBasis != "single_observation" || rep.Times.DurationMS != 0 {
		t.Fatalf("one sample in a closed window must not fabricate a duration: %+v", rep.Times)
	}
	found := false
	for _, kv := range rep.Summary.Noc {
		if kv.K == "Duration" && strings.Contains(kv.V, "exact duration unknown") {
			found = true
		}
	}
	if !found {
		t.Fatal("NOC must state the single-observation duration honestly")
	}
	if !strings.Contains(rep.States.SeverityBasis, "synthetic http 5xx") ||
		!strings.Contains(rep.States.SeverityBasis, "1 high") {
		t.Fatalf("severity basis must name its carrier and mix: %q", rep.States.SeverityBasis)
	}
	// no grounded topo edges → root not identified → escalation owner restrained
	if rep.RootCause.Identified {
		t.Fatal("no grounded convergence — root must not be identified")
	}
	if rep.Ownership.EscalationOwner != "Pending localization" {
		t.Fatalf("escalation owner = %q — a confirmed but unlocalized fault hands no one the pager",
			rep.Ownership.EscalationOwner)
	}
}

// Epic D2: the causal cascade reaches the exported report (its terminal consumer).
func TestRcaReportCarriesCascade(t *testing.T) {
	hyp := testHyp("sig.ent.middle-mile.ipsec-underlay-down", 1.0, "confirmed",
		[]string{"ipsec_underlay_status"}, nil, nil, "isp", false)
	hyp["causal_chain"] = []map[string]any{
		{"stage": "Underlay path to the tunnel peer", "witnessed": true, "root": true, "kinds": []string{"ipsec_underlay_status"}},
		{"stage": "IKE/IPsec tunnel", "witnessed": true, "kinds": []string{"ipsec_tunnel_status"}},
		{"stage": "Routing over the underlay (BGP)", "witnessed": false, "note": "No routing-protocol signals seen on this path"},
	}
	meta := testMeta("open", "confirmed", "sig.ent.middle-mile.ipsec-underlay-down", hyp)
	sigs := []map[string]any{
		testSig("ipsec_underlay_status", "control_plane", "ipsec:gw", "seam", "sm-1", "crit", "2026-07-12 18:12:00", true, nil),
	}
	rep := buildTestReport(t, meta, sigs)
	if len(rep.Cascade) != 3 || !rep.Cascade[0].Root || !rep.Cascade[0].Witnessed {
		t.Fatalf("cascade = %+v", rep.Cascade)
	}
	if rep.Cascade[1].Note != "ipsec tunnel status" {
		t.Fatalf("witnessed rung note must humanize its kinds: %q", rep.Cascade[1].Note)
	}
	htmlBytes, err := renderRcaReportHTML(rep)
	if err != nil {
		t.Fatal(err)
	}
	html := string(htmlBytes)
	for _, want := range []string{"How the failure propagated", "likely origin", "not observed"} {
		if !strings.Contains(html, want) {
			t.Fatalf("report HTML missing %q", want)
		}
	}
}

// Owner feedback batch: dimensional states, escalation execution, transaction detail.
func TestRcaReportDimensionalStatesAndEscalation(t *testing.T) {
	meta := testMeta("open", "confirmed", "sig.ent.cloud.ipsec-tunnel-down",
		testHyp("sig.ent.cloud.ipsec-tunnel-down", 0.9, "confirmed",
			[]string{"ipsec_tunnel_status"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("ipsec_tunnel_status", "control_plane", "ipsec:gw", "seam", "sm-1", "crit", "2026-07-12 18:12:00", true,
			map[string]any{"attrs": `{"state":"down","seam_id":"sm-1"}`}),
		testSig("synthetic_http_5xx", "active_probe", "prober", "app", "portal", "high", "2026-07-12 18:12:30", true,
			map[string]any{"probe_scope": "customer_path",
				"attrs": `{"target":"https://portal/health","method":"GET","status_code":503,"fail_class":"timeout","dns_ms":4.2,"total_ms":812.5}`}),
	}
	rep := buildTestReport(t, meta, sigs)
	if rep.States.Symptom != "confirmed" {
		t.Fatalf("symptom = %q", rep.States.Symptom)
	}
	// P1.3: the fault DOMAIN confirms; the MECHANISM (why it failed) requires
	// its own causal evidence and stays under investigation.
	if rep.States.FaultDomain != "confirmed" || rep.States.Mechanism != "under_investigation" {
		t.Fatalf("domain/mechanism = %s/%s", rep.States.FaultDomain, rep.States.Mechanism)
	}
	// no grounded convergence and no seam context in this fixture → root honest
	if rep.States.RootCauseState == "" {
		t.Fatal("root cause state must always be stated")
	}
	// escalation conditions hold at report time → executed, not future tense
	if rep.Decision.EscalationState != "triggered" || rep.Decision.EscalationAt == "" {
		t.Fatalf("escalation = %s at %q", rep.Decision.EscalationState, rep.Decision.EscalationAt)
	}
	// the actual failed transaction is surfaced with per-phase results
	tx := rep.Signals.Probe.LastTransaction
	if tx == nil || tx.StatusCode != 503 || tx.TotalMs == nil || *tx.TotalMs != 812.5 {
		t.Fatalf("transaction = %+v", tx)
	}
	// a symptom-classification hypothesis is labeled as one
	if got := rcaHypothesisType("sig.ent.app.saas-experience-degraded"); got != "symptom classification" {
		t.Fatalf("type = %q", got)
	}
}

// Management-summary length discipline (mission item 4): compose-then-trim to
// the 130–160-word target — whole sentences drop in deterministic priority
// order; the what-happened / still-happening / impact sentences never drop;
// trimming is surfaced as a P2 quality warning.
func TestManagementSummaryTrimOverflow(t *testing.T) {
	sent := func(words int, marker string) string {
		return marker + " " + strings.Repeat("w ", words-1)
	}
	sents := []rcaSummarySentence{
		{text: sent(40, "WHAT"), protected: true},
		{text: sent(40, "STILL"), protected: true},
		{text: sent(40, "IMPACT"), protected: true},
		{text: sent(40, "CAUSE"), dropRank: 2},
		{text: sent(30, "DECISION"), dropRank: 1},
		{text: sent(30, "MONITORING"), dropRank: 3},
	}
	out, trimmed := rcaComposeSummary(sents, rcaMgmtWordCap)
	if !trimmed {
		t.Fatal("220-word summary did not trim")
	}
	if n := len(strings.Fields(out)); n > rcaMgmtWordCap {
		t.Fatalf("still %d words after trim (cap %d)", n, rcaMgmtWordCap)
	}
	for _, protected := range []string{"WHAT", "STILL", "IMPACT"} {
		if !strings.Contains(out, protected) {
			t.Fatalf("protected sentence %q dropped: %s", protected, out)
		}
	}
	// deterministic order: MONITORING (rank 3) drops first, then CAUSE (rank 2)
	if strings.Contains(out, "MONITORING") || strings.Contains(out, "CAUSE") {
		t.Fatalf("drop priority violated: %s", out)
	}
	if !strings.Contains(out, "DECISION") {
		t.Fatalf("decision dropped although cap already met: %s", out)
	}

	// under the cap: nothing trims, text joins unchanged
	short := []rcaSummarySentence{
		{text: "One.", protected: true}, {text: "Two.", dropRank: 1},
	}
	out2, trimmed2 := rcaComposeSummary(short, rcaMgmtWordCap)
	if trimmed2 || out2 != "One. Two." {
		t.Fatalf("under-cap compose changed text: %q trimmed=%v", out2, trimmed2)
	}

	// protected-only overflow: never truncate mid-sentence — stays over cap
	// (the validator raises management_summary_over_length instead).
	huge := []rcaSummarySentence{{text: sent(200, "WHAT"), protected: true}}
	out3, trimmed3 := rcaComposeSummary(huge, rcaMgmtWordCap)
	if trimmed3 || len(strings.Fields(out3)) != 200 {
		t.Fatalf("protected sentence was altered: %d words trimmed=%v", len(strings.Fields(out3)), trimmed3)
	}

	// end-to-end: a trimmed report carries the P2 warning
	rep := rcaReport{Summary: rcaReportSummaries{Management: "short"}, mgmtTrimmed: true,
		States: rcaReportStates{Incident: "active", Recovery: "not_observed"}}
	rep.Decision.EscalationState = "armed"
	q := validateRcaReport(&rep, rcaTestNow)
	found := false
	for _, w := range q.Warnings {
		if w.Code == "management_summary_trimmed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("trimmed summary missing P2 warning: %+v", q.Warnings)
	}
}
