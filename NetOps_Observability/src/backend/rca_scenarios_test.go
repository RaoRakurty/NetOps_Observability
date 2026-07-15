package main

// rca_scenarios_test.go — the table-driven generic scenario harness (mission
// TEST MATRIX). One harness, thirty scenario fact-sets, one shared invariant
// suite: the six regression fixtures are rows in the same table as every other
// issue family — never six special-cased tests.
//
// Every scenario's report must additionally pass the cross-scenario invariants
// (assertRcaInvariants) and the StateConsistencyValidator (Quality.Passed).

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// ---- harness ------------------------------------------------------------------

type rcaScenario struct {
	name   string
	meta   map[string]any
	sigs   []map[string]any
	ticket map[string]any
	// expectations (empty string = don't assert)
	incident        string
	recovery        string
	recoveredAt     string // "" = must be uncaptured; "-" = don't assert
	rootState       string
	faultDomain     string
	impactRU        string
	sevIncident     string
	ticketState     string
	reportType      string
	firstActionOpP  string   // operational priority of action[0]
	actionMustHave  []string // substrings that must appear in some action
	actionMustNot   []string // substrings that must appear in NO action text/output
	mgmtMustContain []string
	custom          func(t *testing.T, rep rcaReport)
}

func runRcaScenario(t *testing.T, sc rcaScenario) rcaReport {
	t.Helper()
	rep := buildRcaReport(rcaReportInput{
		ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Meta: sc.meta, Signals: sc.sigs,
		Ticket: sc.ticket, Policy: defaultIncidentPolicy("t1"), Now: rcaTestNow,
	})
	if sc.incident != "" && rep.States.Incident != sc.incident {
		t.Fatalf("incident = %q, want %q", rep.States.Incident, sc.incident)
	}
	if sc.recovery != "" && rep.States.Recovery != sc.recovery {
		t.Fatalf("recovery = %q, want %q (basis: %s)", rep.States.Recovery, sc.recovery, rep.States.RecoveryBasis)
	}
	switch sc.recoveredAt {
	case "-":
	case "":
		if rep.Times.RecoveredCaptured {
			t.Fatalf("recovered_at = %q — must be uncaptured", rep.Times.RecoveredAt)
		}
	default:
		if !rep.Times.RecoveredCaptured || !strings.Contains(rep.Times.RecoveredAt, sc.recoveredAt) {
			t.Fatalf("recovered_at = %q, want %q", rep.Times.RecoveredAt, sc.recoveredAt)
		}
	}
	if sc.rootState != "" && rep.States.RootCauseState != sc.rootState {
		t.Fatalf("root state = %q, want %q", rep.States.RootCauseState, sc.rootState)
	}
	if sc.faultDomain != "" && rep.States.FaultDomain != sc.faultDomain {
		t.Fatalf("fault domain = %q, want %q", rep.States.FaultDomain, sc.faultDomain)
	}
	if sc.impactRU != "" && rep.States.ImpactRealUser != sc.impactRU {
		t.Fatalf("impact_real_user = %q, want %q", rep.States.ImpactRealUser, sc.impactRU)
	}
	if sc.sevIncident != "" && rep.States.SeverityIncident != sc.sevIncident {
		t.Fatalf("severity_incident = %q (codes %v), want %q",
			rep.States.SeverityIncident, rep.States.SeverityReasonCodes, sc.sevIncident)
	}
	if sc.ticketState != "" && rep.States.Ticket != sc.ticketState {
		t.Fatalf("ticket = %q, want %q", rep.States.Ticket, sc.ticketState)
	}
	if sc.reportType != "" && rep.ReportType != sc.reportType {
		t.Fatalf("report type = %q, want %q", rep.ReportType, sc.reportType)
	}
	if sc.firstActionOpP != "" {
		if len(rep.Actions) == 0 || rep.Actions[0].OperationalPriority != sc.firstActionOpP {
			t.Fatalf("first action priority: %+v, want %s", rep.Actions, sc.firstActionOpP)
		}
	}
	allActions := ""
	for _, a := range rep.Actions {
		allActions += a.Action + " ⇒ " + a.ExpectedResult + "\n"
	}
	for _, want := range sc.actionMustHave {
		if !strings.Contains(strings.ToLower(allActions), strings.ToLower(want)) {
			t.Fatalf("actions missing %q:\n%s", want, allActions)
		}
	}
	for _, banned := range sc.actionMustNot {
		if strings.Contains(strings.ToLower(allActions), strings.ToLower(banned)) {
			t.Fatalf("actions contain banned %q:\n%s", banned, allActions)
		}
	}
	for _, want := range sc.mgmtMustContain {
		if !strings.Contains(rep.Summary.Management, want) {
			t.Fatalf("management summary missing %q: %s", want, rep.Summary.Management)
		}
	}
	assertRcaInvariants(t, rep)
	if sc.custom != nil {
		sc.custom(t, rep)
	}
	return rep
}

// assertRcaInvariants — the mission's REQUIRED INVARIANT TESTS, applied to
// every scenario (and to every randomized property-test report).
func assertRcaInvariants(t *testing.T, rep rcaReport) {
	t.Helper()
	st := rep.States
	fail := func(f string, args ...any) {
		t.Helper()
		t.Fatalf("INVARIANT: "+f+"\nstates: %+v\ntimes: %+v\nquality: %+v",
			append(args, st, rep.Times, rep.Quality)...)
	}
	// the builder must never emit a document that fails its own gate
	if !rep.Quality.Passed {
		fail("builder produced a report failing its own consistency gate: %+v", rep.Quality.Errors)
	}
	// no Closed/Recovered + Recovery not observed
	if (st.Incident == "closed" || st.Incident == "recovered") && st.Recovery == "not_observed" {
		fail("closed/recovered with recovery not_observed")
	}
	// no recovered_at before last anomaly
	if rep.Times.RecoveredCaptured && rep.Times.LastAnomalous != "" {
		rec, ok1 := parseChTS(strings.TrimSuffix(rep.Times.RecoveredAt, " UTC"))
		last, ok2 := parseChTS(strings.TrimSuffix(rep.Times.LastAnomalous, " UTC"))
		if ok1 && ok2 && rec.Before(last) {
			fail("recovered_at %s before last anomaly %s", rep.Times.RecoveredAt, rep.Times.LastAnomalous)
		}
	}
	// no monitoring before/without service-level recovery
	if rep.Times.MonitoringUntil != "" && !rep.Times.RecoveredCaptured {
		fail("monitoring window without a recovery trigger")
	}
	// component recovery must never be presented as incident recovery
	if st.Recovery == "component_only" && (st.Incident == "recovered" || rep.Times.RecoveredCaptured) {
		fail("component-only recovery presented as incident recovery")
	}
	// no root-cause confirmation without mechanism and object
	if st.RootCauseState == "confirmed" && (rep.RootCause.Mechanism == "" || rep.RootCause.Object == "") {
		fail("root cause confirmed without mechanism+object")
	}
	if rep.RootCause.Identified && (rep.RootCause.Mechanism == "" || rep.RootCause.Object == "") {
		fail("root_cause.identified without mechanism+object")
	}
	// no customer-impact confirmation without real-user evidence
	if st.Impact == "confirmed" && st.ImpactRealUser != "confirmed" {
		fail("impact confirmed without confirmed real-user impact")
	}
	// no "no impact" claim without sufficient multi-class coverage (P1.6)
	if st.Impact == "none_detected" && (st.ImpactSynthetic != "none_detected" || st.ImpactRealUser != "none_detected") {
		fail("impact none_detected without multi-class coverage (syn=%s ru=%s)", st.ImpactSynthetic, st.ImpactRealUser)
	}
	// monitoring/decision copy never claims recovery without recovery evidence
	if strings.Contains(strings.ToLower(rep.Decision.Reason), "has recovered") && st.Recovery != "explicitly_confirmed" {
		fail("decision copy claims recovery while recovery is %q: %s", st.Recovery, rep.Decision.Reason)
	}
	// no CRIT solely from a single uncorroborated stream
	if st.SeverityIncident == "crit" {
		for _, c := range st.SeverityReasonCodes {
			if c == "single_evidence_class" || c == "single_observer" {
				fail("CRIT incident severity from single uncorroborated stream")
			}
		}
	}
	// validation scenarios carry no production severity and never an open recommendation
	if rep.Validation {
		if st.SeverityIncident != "not_applicable" {
			fail("validation scenario with production severity %q", st.SeverityIncident)
		}
		if rep.Decision.TicketRecommended == "open" {
			fail("validation scenario recommends opening a production ticket")
		}
	}
	// ticket/escalation contradiction must always be explained
	if rep.Decision.EscalationState == "triggered" &&
		(st.Ticket == "not_opened" || st.Ticket == "held") && rep.Decision.TicketExecutionNote == "" {
		fail("escalation triggered with unexplained %s ticket", st.Ticket)
	}
	// every action: operational priority present; family-consistent output
	for i, a := range rep.Actions {
		if a.OperationalPriority != "P1" && a.OperationalPriority != "P2" {
			fail("action[%d] without operational priority", i)
		}
	}
	// hypotheses: no confirmed-and-ruled-out; no symptom ranked as origin
	for i, h := range rep.Hypotheses {
		if h.Contradicted && strings.EqualFold(h.Label, "confirmed") {
			fail("hypothesis[%d] confirmed AND ruled out", i)
		}
		if h.Type == "symptom classification" && strings.Contains(h.CausalRole, "origin") && h.CausalRole != "ruled_out_as_origin" {
			fail("hypothesis[%d] symptom ranked as causal origin", i)
		}
	}
	// duration honesty
	if rep.Times.DurationBasis == "to_recovery" && !rep.Times.RecoveredCaptured {
		fail("duration to_recovery without captured recovery")
	}
	// management-summary length discipline: over-cap only when protected
	// sentences alone exceed the cap, and then only with a quality warning
	if n := len(strings.Fields(rep.Summary.Management)); n > rcaMgmtWordCap {
		warned := false
		for _, w := range rep.Quality.Warnings {
			if w.Code == "management_summary_over_length" {
				warned = true
			}
		}
		if !warned {
			fail("management summary %d words over cap %d without a quality warning", n, rcaMgmtWordCap)
		}
	}
	// banned wording in rendered HTML (raw rule syntax, banned phrases)
	html, err := renderRcaReportHTML(rep)
	if err != nil {
		fail("render: %v", err)
	}
	doc := strings.ToLower(string(html))
	for _, banned := range []string{
		"went dark", "where it breaks", "real network issue",
		"matches this issue type", "would be owned by", "check(s)", "signal(s)",
	} {
		if strings.Contains(doc, banned) {
			fail("rendered HTML contains banned wording %q", banned)
		}
	}
}

// ---- fixture builders ---------------------------------------------------------------

func sigFlowAnomaly(ts, sev string) map[string]any {
	return testSig("flow_volume_anomaly", "passive_flow", "exporter-cloud-1", "interface", "vpc-flow-if1", sev, ts, true, nil)
}

func sigProbeLoss(ts, sev, observer, target string) map[string]any {
	return testSig("probe_loss", "active_probe", observer, "path", observer+"->"+target, sev, ts, true,
		map[string]any{"probe_scope": "customer_path"})
}

func sigProbeClear(ts, observer, target string) map[string]any {
	return testSig("probe_loss_clear", "active_probe", observer, "path", observer+"->"+target, "info", ts, false,
		map[string]any{"clear_ts": ts})
}

func sigStatusDown(kind, ts, entity string) map[string]any {
	return testSig(kind, "control_plane", "gw-1", "seam", entity, "crit", ts, true,
		map[string]any{"attrs": `{"state":"down","seam_id":"` + entity + `"}`})
}

func sigStatusUp(kind, ts, entity string) map[string]any {
	return testSig(kind, "control_plane", "gw-1", "seam", entity, "info", ts, false,
		map[string]any{"attrs": `{"state":"up","seam_id":"` + entity + `"}`})
}

// hyp with playbook first-steps (potentially cross-family — the planner gates them)
func testHypSteps(id string, conf float64, label string, satisfied []string, owner string, steps ...string) map[string]any {
	h := testHyp(id, conf, label, satisfied, nil, nil, owner, false)
	h["verdict"].(map[string]any)["first_steps"] = steps
	return h
}

// ---- the six regression fixtures ------------------------------------------------------

// (1) P-261D09 class: flow-only cloud private-connectivity anomaly, window
// closed by quiescence. No recovery claim, no root cause, no Direct Connect /
// BGP actions, P2 validation priority, indicator impact, capped severity.
func TestScenarioFlowOnlyCloudConnectivity(t *testing.T) {
	meta := testMeta("closed", "suspected", "sig.ent.cloud.private-connectivity-down",
		testHypSteps("sig.ent.cloud.private-connectivity-down", 0.45, "suspected",
			[]string{"flow_volume_anomaly"}, "cloud_provider",
			"Validate the Direct Connect virtual interface and BGP session state",
			"Check the IPsec tunnel and IKE SA state on the VPN gateway"))
	sc := rcaScenario{
		name:           "flow-only cloud connectivity",
		meta:           meta,
		sigs:           []map[string]any{sigFlowAnomaly("2026-07-12 18:10:00", "crit")},
		incident:       "no_longer_observed",
		recovery:       "inferred",
		recoveredAt:    "",
		rootState:      "under_investigation",
		impactRU:       "indicator_detected",
		sevIncident:    "warn", // capped: single class, single observer, unconfirmed
		ticketState:    "held",
		firstActionOpP: "P2",
		actionMustHave: []string{"source, destination", "baseline", "collector"},
		actionMustNot:  []string{"Direct Connect", "BGP", "IKE"},
		custom: func(t *testing.T, rep rcaReport) {
			if rep.RootCause.Identified {
				t.Fatal("flow-only anomaly must not identify a root cause")
			}
			if strings.Contains(rep.Title, "recovered") {
				t.Fatalf("title claims recovery: %q", rep.Title)
			}
			// severity cap carries reason codes
			has := false
			for _, c := range rep.States.SeverityReasonCodes {
				if c == "single_evidence_class" {
					has = true
				}
			}
			if !has {
				t.Fatalf("severity codes missing cap basis: %v", rep.States.SeverityReasonCodes)
			}
			// P1.5/P1.6 residue: one uncorroborated flow class must NEVER render
			// a "no impact" claim — badge or management sentence.
			if rep.States.Impact == "none_detected" {
				t.Fatalf("flow-only case claims impact none_detected")
			}
			if rep.States.Impact != "indicator_detected" {
				t.Fatalf("flow-only impact = %q, want indicator_detected", rep.States.Impact)
			}
			if strings.Contains(rep.Summary.Management, "No customer impact") {
				t.Fatalf("management summary claims no impact from one flow class: %s", rep.Summary.Management)
			}
			// no recovery evidence → monitoring copy states "no longer observed",
			// never a recovery claim.
			if rep.Decision.Decision != "Monitor" {
				t.Fatalf("decision = %q, want Monitor", rep.Decision.Decision)
			}
			if !strings.Contains(rep.Decision.Reason, "no recovery evidence was captured") {
				t.Fatalf("monitoring copy missing no-recovery statement: %s", rep.Decision.Reason)
			}
			if strings.Contains(strings.ToLower(rep.Decision.Reason), "has recovered") {
				t.Fatalf("monitoring copy claims recovery: %s", rep.Decision.Reason)
			}
		},
	}
	runRcaScenario(t, sc)
}

// (2/4) P-03C796 / P-F4157A class: underlay recovers at 16:22 while end-to-end
// probes keep failing until 16:33 — component recovery + residual degradation,
// incident stays ACTIVE, no recovered_at, carrier pending demarcation.
func TestScenarioUnderlayRecoveryServiceStillFailing(t *testing.T) {
	meta := testMeta("open", "confirmed", "sig.ent.middle-mile.ipsec-underlay-down",
		testHypSteps("sig.ent.middle-mile.ipsec-underlay-down", 0.95, "confirmed",
			[]string{"ipsec_underlay_status", "probe_loss"}, "isp",
			"Validate the local egress interface and errors toward the underlay peer",
			"Trace the route to the tunnel's public peer address"))
	sigs := []map[string]any{
		sigStatusDown("ipsec_underlay_status", "2026-07-12 16:19:11", "sm-azure-1"),
		sigProbeLoss("2026-07-12 16:20:00", "crit", "lan-vantage", "10.60.10.10"),
		sigProbeLoss("2026-07-12 16:27:00", "crit", "lan-vantage", "10.60.10.10"),
		sigStatusUp("ipsec_underlay_status", "2026-07-12 16:22:20", "sm-azure-1"),
		sigProbeLoss("2026-07-12 16:33:51", "crit", "lan-vantage", "10.60.10.10"),
	}
	sc := rcaScenario{
		name:        "underlay component recovery, service failing",
		meta:        meta,
		sigs:        sigs,
		incident:    "active",
		recovery:    "failed_validation",
		recoveredAt: "",
		rootState:   "under_investigation",
		faultDomain: "confirmed",
		custom: func(t *testing.T, rep rcaReport) {
			if rep.Times.ComponentRecoveredAt == "" || !strings.Contains(rep.Times.ComponentRecoveredAt, "16:22:20") {
				t.Fatalf("component recovery time = %q", rep.Times.ComponentRecoveredAt)
			}
			if rep.Times.DurationBasis == "to_recovery" {
				t.Fatal("duration must not measure to the component recovery")
			}
			// residual-degradation phase must exist and be narrated
			foundResidual := false
			for _, p := range rep.Phases {
				if p.Type == "residual_degradation" {
					foundResidual = true
				}
			}
			if !foundResidual {
				t.Fatalf("phases missing residual_degradation: %+v", rep.Phases)
			}
			if !strings.Contains(rep.Summary.Management, "residual degradation") {
				t.Fatalf("management summary must explain residual degradation: %s", rep.Summary.Management)
			}
			// carrier ownership pending demarcation, NetOps owns investigation
			if rep.Ownership.EscalationOwner == "ISP / carrier" || rep.Ownership.EscalationOwner == "Carrier" {
				t.Fatalf("carrier handed ownership without demarcation: %+v", rep.Ownership)
			}
			if rep.Ownership.ExternalCandidate == "" || rep.Ownership.Demarcation != "local_checks_pending" {
				t.Fatalf("demarcation assessment missing: %+v", rep.Ownership)
			}
			// seam is localization, not root cause
			if rep.RootCause.Identified {
				t.Fatal("seam grounding must not identify a root cause")
			}
			// confirmed + active + escalation triggered but no ticket link →
			// explained on the document
			if rep.Decision.EscalationState == "triggered" && rep.Decision.TicketExecutionNote == "" {
				t.Fatal("ticket/escalation split not explained")
			}
			// P1 restoration work exists while the service is failing
			hasP1 := false
			for _, a := range rep.Actions {
				if a.OperationalPriority == "P1" {
					hasP1 = true
				}
			}
			if !hasP1 {
				t.Fatalf("no P1 action while end-to-end failure persists: %+v", rep.Actions)
			}
		},
	}
	runRcaScenario(t, sc)
}

// (3/5) P-DF0A95 / P-FEC191 class: tunnel down 11s (component recovers fast),
// probes fail ~15 minutes, then a service-level clear — the incident duration
// runs to SERVICE recovery, never the 11-second component window.
func TestScenarioTunnelShortComponentLongResidual(t *testing.T) {
	meta := testMeta("closed", "confirmed", "sig.ent.cloud.ipsec-tunnel-down",
		testHypSteps("sig.ent.cloud.ipsec-tunnel-down", 0.9, "confirmed",
			[]string{"ipsec_tunnel_status", "probe_loss"}, "netops",
			"Verify IKE and child-SA state on the VPN gateway"))
	sigs := []map[string]any{
		sigStatusDown("ipsec_tunnel_status", "2026-07-12 17:44:24", "sm-aws-1"),
		sigStatusUp("ipsec_tunnel_status", "2026-07-12 17:44:35", "sm-aws-1"),
		sigProbeLoss("2026-07-12 17:45:00", "crit", "client-vantage", "10.60.10.10"),
		sigProbeLoss("2026-07-12 17:50:51", "crit", "client-vantage", "10.60.10.10"),
		sigProbeClear("2026-07-12 17:59:30", "client-vantage", "10.60.10.10"),
	}
	sc := rcaScenario{
		name:        "short tunnel outage, long residual, full recovery",
		meta:        meta,
		sigs:        sigs,
		incident:    "recovered",
		recovery:    "explicitly_confirmed",
		recoveredAt: "17:59:30",
		rootState:   "under_investigation",
		custom: func(t *testing.T, rep rcaReport) {
			// duration to SERVICE recovery (~15m), never 11 seconds
			if rep.Times.DurationBasis != "to_recovery" {
				t.Fatalf("duration basis = %q", rep.Times.DurationBasis)
			}
			if rep.Times.DurationMS < 10*60*1000 {
				t.Fatalf("duration %dms — measured to component recovery, not service recovery", rep.Times.DurationMS)
			}
			// the IKE action IS applicable here (ipsec evidence participated)
			hasIke := false
			for _, a := range rep.Actions {
				if strings.Contains(a.Action, "IKE") {
					hasIke = true
					if !strings.Contains(a.ExpectedResult, "IKE/child-SA") {
						t.Fatalf("IKE action carries wrong expected output: %q", a.ExpectedResult)
					}
				}
			}
			if !hasIke {
				t.Fatal("IPsec case with tunnel evidence must keep its IKE first-step")
			}
			// phases: component_recovery + residual_degradation + service_recovery
			types := map[string]bool{}
			for _, p := range rep.Phases {
				types[p.Type] = true
			}
			for _, want := range []string{"component_recovery", "residual_degradation", "service_recovery"} {
				if !types[want] {
					t.Fatalf("phases missing %s: %+v", want, rep.Phases)
				}
			}
		},
	}
	runRcaScenario(t, sc)
}

// variant: same case but NO service clear — the incident must not close clean.
func TestScenarioTunnelResidualNoServiceRecovery(t *testing.T) {
	meta := testMeta("closed", "confirmed", "sig.ent.cloud.ipsec-tunnel-down",
		testHyp("sig.ent.cloud.ipsec-tunnel-down", 0.9, "confirmed",
			[]string{"ipsec_tunnel_status", "probe_loss"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		sigStatusDown("ipsec_tunnel_status", "2026-07-12 17:44:24", "sm-aws-1"),
		sigStatusUp("ipsec_tunnel_status", "2026-07-12 17:44:35", "sm-aws-1"),
		sigProbeLoss("2026-07-12 17:45:00", "crit", "client-vantage", "10.60.10.10"),
		sigProbeLoss("2026-07-12 17:50:51", "crit", "client-vantage", "10.60.10.10"),
	}
	runRcaScenario(t, rcaScenario{
		name: "tunnel residual, no service recovery", meta: meta, sigs: sigs,
		incident: "no_longer_observed", recovery: "failed_validation", recoveredAt: "",
	})
}

// (6) P-FF7B75 class: single SaaS flow anomaly. Symptom stays a symptom, no
// CRIT, no IPsec/IKE contamination, flow-first validation actions.
func TestScenarioSingleFlowSaaSAnomaly(t *testing.T) {
	meta := testMeta("closed", "suspected", "sig.ent.app.saas-experience-degraded",
		testHypSteps("sig.ent.app.saas-experience-degraded", 0.4, "suspected",
			[]string{"flow_volume_anomaly"}, "app_team",
			"Identify the failing protocol stage of the synthetic check",
			"Examine the flow anomaly and verify IKE and child-SA output on the gateway"))
	sc := rcaScenario{
		name:           "single flow SaaS anomaly",
		meta:           meta,
		sigs:           []map[string]any{sigFlowAnomaly("2026-07-12 23:54:00", "crit")},
		incident:       "no_longer_observed",
		recovery:       "inferred",
		recoveredAt:    "",
		rootState:      "under_investigation",
		faultDomain:    "not_localized", // symptom top hypothesis never localizes
		impactRU:       "indicator_detected",
		sevIncident:    "warn",
		firstActionOpP: "P2",
		actionMustHave: []string{"baseline"},
		actionMustNot:  []string{"IKE", "child-SA", "synthetic check"},
		custom: func(t *testing.T, rep rcaReport) {
			if len(rep.Hypotheses) == 0 {
				t.Fatal("hypothesis row expected")
			}
			h := rep.Hypotheses[0]
			if h.Type != "symptom classification" || h.CausalRole != "symptom" || h.CandidacyState != "not_ranked_as_cause" {
				t.Fatalf("symptom taxonomy wrong: %+v", h)
			}
			// no team is named the escalation owner before localization
			if rep.Ownership.EscalationOwner == "Application team" {
				t.Fatal("application team named before localization")
			}
		},
	}
	runRcaScenario(t, sc)
}

// ---- generic scenario matrix (7-30) --------------------------------------------------

func TestScenarioMatrixGeneric(t *testing.T) {
	mk := func(sc rcaScenario) rcaScenario { return sc }
	scenarios := []rcaScenario{
		// (7) LAN interface down — device/control evidence, confirmed
		mk(rcaScenario{
			name: "lan interface down",
			meta: testMeta("open", "confirmed", "sig.ent.access.uplink-down",
				testHypSteps("sig.ent.access.uplink-down", 0.9, "confirmed",
					[]string{"interface_down", "probe_loss"}, "netops",
					"Validate interface admin/oper state and error counters on the access switch")),
			sigs: []map[string]any{
				testSig("interface_down", "control_plane", "lan-sw1", "interface", "lan-sw1:Gi0/1", "crit", "2026-07-12 18:00:00", true, nil),
				sigProbeLoss("2026-07-12 18:00:30", "crit", "lan-vantage", "10.10.1.1"),
			},
			incident: "active", faultDomain: "confirmed", rootState: "under_investigation",
			actionMustHave: []string{"interface"},
		}),
		// (8) WAN circuit loss with carrier candidate → demarcation pending
		mk(rcaScenario{
			name: "wan circuit loss",
			meta: testMeta("open", "confirmed", "sig.ent.middle-mile.dia-egress-loss",
				testHypSteps("sig.ent.middle-mile.dia-egress-loss", 0.85, "confirmed",
					[]string{"probe_loss", "bgp_adjacency_change"}, "isp",
					"Trace the route toward the egress peer and record per-hop loss")),
			sigs: []map[string]any{
				testSig("bgp_adjacency_change", "control_plane", "wan-r1", "device", "wan-r1", "crit", "2026-07-12 18:00:00", true, nil),
				sigProbeLoss("2026-07-12 18:00:20", "crit", "branch-vantage", "8.8.8.8"),
			},
			incident: "active",
			custom: func(t *testing.T, rep rcaReport) {
				if rcaExternalOwnerTeams[rep.Ownership.EscalationOwner] {
					t.Fatalf("carrier owns escalation without demarcation: %+v", rep.Ownership)
				}
			},
		}),
		// (9) SD-WAN overlay down with healthy underlay — overlay evidence only
		mk(rcaScenario{
			name: "sdwan overlay down healthy underlay",
			meta: testMeta("open", "suspected", "sig.ent.sdwan.tunnel-flap",
				testHypSteps("sig.ent.sdwan.tunnel-flap", 0.5, "suspected",
					[]string{"ipsec_tunnel_status"}, "sdwan_vendor",
					"Review overlay tunnel state history on the SD-WAN controller")),
			sigs: []map[string]any{
				sigStatusDown("ipsec_tunnel_status", "2026-07-12 18:00:00", "sdwan-ovl-1"),
			},
			incident: "active", rootState: "under_investigation",
		}),
		// (10) SD-WAN underlay down with tunnel consequence — both confirmed
		// observations; the tunnel is a downstream consequence
		mk(rcaScenario{
			name: "sdwan underlay down tunnel consequence",
			meta: testMeta("open", "confirmed", "sig.ent.middle-mile.ipsec-underlay-down",
				testHypSteps("sig.ent.middle-mile.ipsec-underlay-down", 0.9, "confirmed",
					[]string{"ipsec_underlay_status", "ipsec_tunnel_status"}, "isp",
					"Validate the local egress interface toward the underlay")),
			sigs: []map[string]any{
				sigStatusDown("ipsec_underlay_status", "2026-07-12 18:00:00", "sm-1"),
				sigStatusDown("ipsec_tunnel_status", "2026-07-12 18:00:10", "sm-1"),
			},
			incident: "active", faultDomain: "confirmed", rootState: "under_investigation",
		}),
		// (11) BGP neighbor down because interface failed
		mk(rcaScenario{
			name: "bgp down from interface",
			meta: testMeta("open", "confirmed", "sig.ent.wan-edge.bgp-peer-down",
				testHypSteps("sig.ent.wan-edge.bgp-peer-down", 0.9, "confirmed",
					[]string{"bgp_adjacency_change", "interface_down"}, "netops",
					"Check neighbor state and last reset reason for the affected BGP peer")),
			sigs: []map[string]any{
				testSig("interface_down", "control_plane", "wan-r2", "interface", "wan-r2:Gi0/0", "crit", "2026-07-12 18:00:00", true, nil),
				testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:00:05", true, nil),
			},
			incident:       "active",
			actionMustHave: []string{"reset reason"},
			custom: func(t *testing.T, rep rcaReport) {
				// BGP adjacency down is a fault condition — root cause (why it
				// went down) stays under investigation
				if rep.States.RootCauseState == "confirmed" {
					t.Fatal("adjacency-down must not confirm root cause")
				}
			},
		}),
		// (12) BGP policy withdrawal with healthy session — control-plane only
		mk(rcaScenario{
			name: "bgp policy withdrawal",
			meta: testMeta("open", "suspected", "sig.ent.wan-edge.routing-instability",
				testHypSteps("sig.ent.wan-edge.routing-instability", 0.5, "suspected",
					[]string{"route_withdrawal"}, "netops",
					"Compare expected prefixes and next hops against the current RIB")),
			sigs: []map[string]any{
				testSig("route_withdrawal", "control_plane", "wan-r2", "device", "wan-r2", "high", "2026-07-12 18:00:00", true, nil),
			},
			incident: "active", sevIncident: "warn", // single stream, suspected
		}),
		// (13) DNS failure — probe evidence with dns kind
		mk(rcaScenario{
			name: "dns failure",
			meta: testMeta("open", "suspected", "sig.ent.internet.dns-impairment",
				testHypSteps("sig.ent.internet.dns-impairment", 0.5, "suspected",
					[]string{"synthetic_dns_failure"}, "netops",
					"Query the configured resolver for the affected name and record the response")),
			sigs: []map[string]any{
				testSig("synthetic_dns_failure", "active_probe", "prober-1", "app", "portal", "high", "2026-07-12 18:00:00", true,
					map[string]any{"probe_scope": "customer_path"}),
			},
			incident:       "active",
			actionMustHave: []string{"DNS response code"},
		}),
		// (14) TCP timeout
		mk(rcaScenario{
			name: "tcp timeout",
			meta: testMeta("open", "suspected", "undetermined", nil),
			sigs: []map[string]any{
				testSig("synthetic_tcp_timeout", "active_probe", "prober-1", "app", "portal", "high", "2026-07-12 18:00:00", true,
					map[string]any{"probe_scope": "customer_path"}),
			},
			incident:       "active",
			actionMustHave: []string{"failed check transaction"},
		}),
		// (15) TLS certificate failure
		mk(rcaScenario{
			name: "tls certificate failure",
			meta: testMeta("open", "confirmed", "sig.ent.app.tls-cert-expired",
				testHypSteps("sig.ent.app.tls-cert-expired", 0.9, "confirmed",
					[]string{"synthetic_tls_failure"}, "app_team",
					"Inspect the TLS handshake and certificate validity window for the endpoint")),
			sigs: []map[string]any{
				testSig("synthetic_tls_failure", "active_probe", "prober-1", "app", "portal", "high", "2026-07-12 18:00:00", true,
					map[string]any{"probe_scope": "customer_path"}),
				testSig("synthetic_tls_failure", "active_probe", "prober-2", "app", "portal", "high", "2026-07-12 18:00:10", true,
					map[string]any{"probe_scope": "customer_path"}),
			},
			incident:       "active",
			actionMustHave: []string{"certificate validity"},
		}),
		// (16) HTTP 503 from multiple vantages
		mk(rcaScenario{
			name: "http 503 multi-vantage",
			meta: testMeta("open", "suspected", "undetermined", nil),
			sigs: []map[string]any{
				testSig("synthetic_http_5xx", "active_probe", "prober-1", "app", "portal", "high", "2026-07-12 18:00:00", true,
					map[string]any{"probe_scope": "customer_path"}),
				testSig("synthetic_http_5xx", "active_probe", "prober-2", "app", "portal", "high", "2026-07-12 18:00:10", true,
					map[string]any{"probe_scope": "customer_path"}),
			},
			incident: "active",
			custom: func(t *testing.T, rep rcaReport) {
				// multi-observer: severity not capped to warn
				if rep.States.SeverityIncident == "warn" {
					t.Fatalf("multi-vantage failure over-capped: %v", rep.States.SeverityReasonCodes)
				}
			},
		}),
		// (17) application content assertion failure — synthetic only
		mk(rcaScenario{
			name: "content assertion failure",
			meta: testMeta("open", "suspected", "undetermined", nil),
			sigs: []map[string]any{
				testSig("synthetic_content_mismatch", "active_probe", "prober-1", "app", "portal", "warn", "2026-07-12 18:00:00", true,
					map[string]any{"probe_scope": "customer_path"}),
			},
			incident: "active", impactRU: "not_observable",
		}),
		// (18) cloud route-table blackhole — cloud change + probe loss
		mk(rcaScenario{
			name: "cloud route blackhole",
			meta: testMeta("open", "suspected", "sig.ent.cloud.private-connectivity-down",
				testHypSteps("sig.ent.cloud.private-connectivity-down", 0.5, "suspected",
					[]string{"probe_loss"}, "cloud_provider",
					"Review the route table for the affected prefix and its next-hop attachment")),
			sigs: []map[string]any{
				sigProbeLoss("2026-07-12 18:00:00", "crit", "client-vantage", "10.60.10.10"),
				testSig("cloud_change", "control_plane", "cloud:acct:usw2", "cloud_resource", "rtb-1", "info", "2026-07-12 17:58:00", false,
					map[string]any{"attrs": `{"resource_id":"rtb-1","event_source":"ec2.amazonaws.com"}`}),
			},
			incident: "active",
			custom: func(t *testing.T, rep rcaReport) {
				if len(rep.CloudChanges) != 1 {
					t.Fatalf("cloud change missing: %+v", rep.CloudChanges)
				}
				if strings.Contains(strings.ToLower(rep.CloudChanges[0].Explanation), "caused") &&
					!strings.Contains(rep.CloudChanges[0].Explanation, "not confirmed") {
					t.Fatalf("change explanation over-claims: %s", rep.CloudChanges[0].Explanation)
				}
			},
		}),
		// (19) security-group/firewall denial — flow reject evidence
		mk(rcaScenario{
			name: "security policy denial",
			meta: testMeta("open", "suspected", "undetermined", nil),
			sigs: []map[string]any{
				testSig("flow_reject_anomaly", "passive_flow", "vpc-flow-1", "interface", "eni-1", "high", "2026-07-12 18:00:00", true, nil),
				testSig("security_policy_change", "control_plane", "cloud:acct:usw2", "cloud_resource", "sg-1", "info", "2026-07-12 17:59:00", false,
					map[string]any{"attrs": `{"resource_id":"sg-1"}`}),
			},
			incident: "active", impactRU: "indicator_detected",
		}),
		// (20) device CPU saturation — device telemetry only
		mk(rcaScenario{
			name: "device cpu saturation",
			meta: testMeta("open", "suspected", "undetermined", nil),
			sigs: []map[string]any{
				testSig("cpu_high", "device_telemetry", "core-r1", "device", "core-r1", "high", "2026-07-12 18:00:00", true, nil),
			},
			incident: "active", sevIncident: "warn", impactRU: "not_observable",
		}),
		// (21) flow collector outage masquerading as traffic loss — indicator only,
		// collector-health action required
		mk(rcaScenario{
			name:     "collector outage masquerade",
			meta:     testMeta("open", "suspected", "undetermined", nil),
			sigs:     []map[string]any{sigFlowAnomaly("2026-07-12 18:00:00", "crit")},
			incident: "active", impactRU: "indicator_detected", sevIncident: "warn",
			actionMustHave: []string{"collector"},
		}),
		// (22) one synthetic check failure — single vantage differential action
		mk(rcaScenario{
			name:     "single synthetic failure",
			meta:     testMeta("open", "suspected", "undetermined", nil),
			sigs:     []map[string]any{sigProbeLoss("2026-07-12 18:00:00", "high", "prober-1", "10.1.1.1")},
			incident: "active", sevIncident: "warn",
			actionMustHave: []string{"independent vantage"},
		}),
		// (23) multiple independent synthetic failures — no warn cap
		mk(rcaScenario{
			name: "multiple synthetic failures",
			meta: testMeta("open", "suspected", "undetermined", nil),
			sigs: []map[string]any{
				sigProbeLoss("2026-07-12 18:00:00", "crit", "prober-1", "10.1.1.1"),
				sigProbeLoss("2026-07-12 18:00:10", "crit", "prober-2", "10.1.1.1"),
				testSig("flow_volume_anomaly", "passive_flow", "exp-1", "interface", "if1", "high", "2026-07-12 18:00:20", true, nil),
			},
			incident: "active",
			custom: func(t *testing.T, rep rcaReport) {
				if rep.States.SeverityIncident == "warn" {
					t.Fatalf("corroborated evidence over-capped: %v", rep.States.SeverityReasonCodes)
				}
			},
		}),
		// (24) real-user impact without synthetic coverage — LB errors only
		mk(rcaScenario{
			name: "real-user impact no synthetic",
			meta: testMeta("open", "confirmed", "sig.ent.app.lb-target-health-failure",
				testHypSteps("sig.ent.app.lb-target-health-failure", 0.9, "confirmed",
					[]string{"lb_5xx", "lb_target_unhealthy"}, "app_team",
					"Check target-health states and backend error rates on the load balancer")),
			sigs: []map[string]any{
				testSig("lb_5xx", "device_telemetry", "alb-1", "app", "portal", "high", "2026-07-12 18:00:00", true, nil),
				testSig("lb_target_unhealthy", "device_telemetry", "alb-1", "app", "portal", "high", "2026-07-12 18:00:10", true, nil),
			},
			incident: "active", impactRU: "confirmed",
			actionMustHave: []string{"target-health"},
		}),
		// (25) explicit component recovery with service still failing (LAN flavor)
		mk(rcaScenario{
			name: "component recovered service failing",
			meta: testMeta("open", "confirmed", "sig.ent.access.uplink-down",
				testHyp("sig.ent.access.uplink-down", 0.9, "confirmed",
					[]string{"interface_down", "probe_loss"}, nil, nil, "netops", false)),
			sigs: []map[string]any{
				testSig("interface_status", "control_plane", "lan-sw1", "interface", "lan-sw1:Gi0/1", "crit", "2026-07-12 18:00:00", true,
					map[string]any{"attrs": `{"state":"down"}`}),
				testSig("interface_status", "control_plane", "lan-sw1", "interface", "lan-sw1:Gi0/1", "info", "2026-07-12 18:05:00", false,
					map[string]any{"attrs": `{"state":"up"}`}),
				sigProbeLoss("2026-07-12 18:07:00", "crit", "lan-vantage", "10.10.1.1"),
			},
			incident: "active", recovery: "failed_validation", recoveredAt: "",
		}),
		// (26) complete service recovery — clean close
		mk(rcaScenario{
			name: "complete service recovery",
			meta: testMeta("closed", "suspected", "undetermined", nil),
			sigs: []map[string]any{
				sigProbeLoss("2026-07-12 18:00:00", "high", "prober-1", "10.1.1.1"),
				sigProbeClear("2026-07-12 18:10:00", "prober-1", "10.1.1.1"),
			},
			incident: "recovered", recovery: "explicitly_confirmed", recoveredAt: "18:10:00",
		}),
		// (27) recurrence inside the monitoring window — anomaly after the clear
		mk(rcaScenario{
			name: "recurrence after recovery evidence",
			meta: testMeta("open", "suspected", "undetermined", nil),
			sigs: []map[string]any{
				sigProbeLoss("2026-07-12 18:00:00", "high", "prober-1", "10.1.1.1"),
				sigProbeClear("2026-07-12 18:10:00", "prober-1", "10.1.1.1"),
				sigProbeLoss("2026-07-12 18:20:00", "high", "prober-1", "10.1.1.1"),
			},
			incident: "active", recovery: "failed_validation", recoveredAt: "",
		}),
		// (28) validation / fault-injection incident — watermarked, suppressed
		mk(rcaScenario{
			name: "validation scenario",
			meta: testMeta("open", "confirmed", "sig.ent.cloud.ipsec-tunnel-down",
				testHyp("sig.ent.cloud.ipsec-tunnel-down", 0.9, "confirmed",
					[]string{"ipsec_tunnel_status"}, nil, nil, "netops", false)),
			sigs: []map[string]any{
				testSig("ipsec_tunnel_status", "control_plane", "gw-1", "seam", "sm-1", "crit", "2026-07-12 18:00:00", true,
					map[string]any{"attrs": `{"state":"down","signal_purpose":"fault_injection"}`}),
			},
			incident: "active", sevIncident: "not_applicable",
			custom: func(t *testing.T, rep rcaReport) {
				if !rep.Validation {
					t.Fatal("validation scenario not detected")
				}
				if rep.Decision.TicketRecommended == "open" {
					t.Fatal("validation scenario recommends production ticket")
				}
			},
		}),
		// (29) cross-tenant evidence must not enrich the report: the builder is a
		// pure function of the tenant-scoped slice — a foreign-tenant signal that
		// somehow appears is still rendered ONLY from the given slice, and the
		// endpoint itself refuses unauthenticated access (see
		// TestRcaReportEndpointRequiresPrincipal). Here: an empty slice yields an
		// empty, honest report — no cross-tenant fabrication paths exist.
		mk(rcaScenario{
			name: "empty slice honest report",
			meta: testMeta("open", "undetermined", "undetermined", nil),
			sigs: nil,
			custom: func(t *testing.T, rep rcaReport) {
				if len(rep.Hypotheses) != 0 || rep.States.Severity != "unknown" {
					t.Fatalf("empty slice fabricated content: %+v", rep.States)
				}
			},
		}),
		// (31) provider-named flow kind (cloud_flow_log rides passive_flow but has
		// no flow_ prefix) — the live P-261D09 residue: the indicator
		// classification is LANE-based, so a provider kind can never fall
		// through to a "none detected" impact claim.
		mk(rcaScenario{
			name: "provider flow kind indicator",
			meta: testMeta("closed", "suspected", "sig.ent.cloud.private-connectivity-down",
				testHyp("sig.ent.cloud.private-connectivity-down", 0.45, "suspected",
					[]string{"cloud_flow_log"}, nil, nil, "cloud_provider", false)),
			sigs: []map[string]any{
				testSig("cloud_flow_log", "passive_flow", "cloud:acct:usw2", "app", "portal", "crit", "2026-07-12 18:10:00", true, nil),
			},
			incident: "no_longer_observed", recovery: "inferred",
			impactRU: "indicator_detected", sevIncident: "warn",
			custom: func(t *testing.T, rep rcaReport) {
				if rep.States.Impact != "indicator_detected" {
					t.Fatalf("impact = %q, want indicator_detected", rep.States.Impact)
				}
				if strings.Contains(rep.Summary.Management, "No customer impact") {
					t.Fatalf("no-impact claim from one provider flow class: %s", rep.Summary.Management)
				}
				if !strings.Contains(rep.Decision.Reason, "no recovery evidence was captured") {
					t.Fatalf("monitoring copy: %s", rep.Decision.Reason)
				}
			},
		}),
		// (32) sufficient multi-class coverage, no impact anomalies — the honest
		// "none detected within coverage" claim is KEPT when both the synthetic
		// and real-traffic axes covered the window cleanly.
		mk(rcaScenario{
			name: "multi-class clean coverage none detected",
			meta: testMeta("open", "confirmed", "sig.ent.access.uplink-down",
				testHypSteps("sig.ent.access.uplink-down", 0.9, "confirmed",
					[]string{"interface_down"}, "netops",
					"Validate interface admin/oper state and error counters on the access switch")),
			sigs: []map[string]any{
				testSig("interface_down", "control_plane", "lan-sw1", "interface", "lan-sw1:Gi0/1", "high", "2026-07-12 18:00:00", true, nil),
				// covering, non-anomalous impact telemetry on BOTH axes
				testSig("probe_rtt", "active_probe", "prober-1", "path", "prober-1->10.10.1.1", "info", "2026-07-12 18:00:00", false, nil),
				testSig("flow_volume", "passive_flow", "exp-1", "interface", "if1", "info", "2026-07-12 18:00:00", false, nil),
			},
			incident: "active", impactRU: "none_detected",
			mgmtMustContain: []string{"No customer impact was detected within available telemetry coverage"},
			custom: func(t *testing.T, rep rcaReport) {
				if rep.States.Impact != "none_detected" {
					t.Fatalf("impact = %q (syn=%s ru=%s), want none_detected",
						rep.States.Impact, rep.States.ImpactSynthetic, rep.States.ImpactRealUser)
				}
			},
		}),
		// (33) partial coverage — only the synthetic axis observed cleanly: the
		// overall no-impact claim is NOT made.
		mk(rcaScenario{
			name: "partial coverage no no-impact claim",
			meta: testMeta("open", "confirmed", "sig.ent.access.uplink-down",
				testHyp("sig.ent.access.uplink-down", 0.9, "confirmed",
					[]string{"interface_down"}, nil, nil, "netops", false)),
			sigs: []map[string]any{
				testSig("interface_down", "control_plane", "lan-sw1", "interface", "lan-sw1:Gi0/1", "high", "2026-07-12 18:00:00", true, nil),
				testSig("probe_rtt", "active_probe", "prober-1", "path", "prober-1->10.10.1.1", "info", "2026-07-12 18:00:00", false, nil),
			},
			incident: "active",
			custom: func(t *testing.T, rep rcaReport) {
				if rep.States.Impact == "none_detected" {
					t.Fatal("partial coverage must not ground a no-impact claim")
				}
				if rep.States.ImpactSynthetic != "none_detected" {
					t.Fatalf("synthetic axis = %q, want its own honest none_detected", rep.States.ImpactSynthetic)
				}
				if strings.Contains(rep.Summary.Management, "No customer impact was detected") {
					t.Fatalf("management claims no impact on partial coverage: %s", rep.Summary.Management)
				}
			},
		}),
		// (34) demarcation PROMOTION path (P1.10 / audit D8): a provider-side
		// alarm AND independent-vantage evidence beyond the customer boundary
		// satisfy the demarcation evidence contract — only then may the external
		// carrier own escalation.
		mk(rcaScenario{
			name: "provider demarcation promotion",
			meta: testMeta("open", "confirmed", "sig.ent.middle-mile.dia-egress-loss",
				testHyp("sig.ent.middle-mile.dia-egress-loss", 0.9, "confirmed",
					[]string{"probe_loss", "provider_alarm"}, nil, nil, "isp", false)),
			sigs: []map[string]any{
				sigProbeLoss("2026-07-12 18:00:00", "crit", "branch-vantage", "8.8.8.8"),
				testSig("provider_alarm", "control_plane", "carrier-noc-feed", "seam", "dia-1", "crit", "2026-07-12 18:01:00", true, nil),
				testSig("independent_vantage_probe", "active_probe", "ext-vantage-1", "path", "ext-vantage-1->peer", "high", "2026-07-12 18:02:00", true, nil),
			},
			incident: "active",
			custom: func(t *testing.T, rep rcaReport) {
				if rep.Ownership.Demarcation != "provider_boundary_confirmed" {
					t.Fatalf("demarcation = %q (basis %q)", rep.Ownership.Demarcation, rep.Ownership.DemarcationBasis)
				}
				if rep.Ownership.EscalationOwner != "ISP / carrier" {
					t.Fatalf("escalation owner = %q, want the demarcated carrier", rep.Ownership.EscalationOwner)
				}
				if rep.Ownership.TechnicalOwner != "NetOps" || rep.Ownership.ExternalCandidate != "ISP / carrier" {
					t.Fatalf("ownership split wrong: %+v", rep.Ownership)
				}
				// the prohibited claim lifts only under the evidence contract
				for _, c := range rep.IssueContext.ProhibitedClaims {
					if c == "external_provider_accountability_without_demarcation" {
						t.Fatalf("prohibition still present after demarcation: %v", rep.IssueContext.ProhibitedClaims)
					}
				}
			},
		}),
		// (35) provider alarm WITHOUT independent-vantage evidence — the
		// demarcation list is not satisfied; carrier stays a candidate.
		mk(rcaScenario{
			name: "provider alarm alone stays pending",
			meta: testMeta("open", "confirmed", "sig.ent.middle-mile.dia-egress-loss",
				testHyp("sig.ent.middle-mile.dia-egress-loss", 0.9, "confirmed",
					[]string{"probe_loss", "provider_alarm"}, nil, nil, "isp", false)),
			sigs: []map[string]any{
				sigProbeLoss("2026-07-12 18:00:00", "crit", "branch-vantage", "8.8.8.8"),
				testSig("provider_alarm", "control_plane", "carrier-noc-feed", "seam", "dia-1", "crit", "2026-07-12 18:01:00", true, nil),
			},
			incident: "active",
			custom: func(t *testing.T, rep rcaReport) {
				if rep.Ownership.Demarcation != "local_checks_pending" {
					t.Fatalf("demarcation = %q", rep.Ownership.Demarcation)
				}
				if rcaExternalOwnerTeams[rep.Ownership.EscalationOwner] {
					t.Fatalf("carrier handed ownership without the demarcation evidence list: %+v", rep.Ownership)
				}
				if !strings.Contains(rep.Ownership.DemarcationBasis, "independent-vantage") {
					t.Fatalf("basis must name the missing evidence: %q", rep.Ownership.DemarcationBasis)
				}
			},
		}),
		// (30) historical/legacy object with empty blobs
		mk(rcaScenario{
			name: "historical legacy compat",
			meta: map[string]any{
				"version": float64(1), "state": "closed", "verdict_tier": "",
				"top_hypothesis": "", "window_start": "2026-06-01 10:00:00",
				"window_end": "2026-06-01 10:30:00", "hypotheses": "", "affected": "",
			},
			sigs:     []map[string]any{sigProbeLoss("2026-06-01 10:05:00", "high", "prober-1", "10.1.1.1")},
			incident: "no_longer_observed", recovery: "inferred",
		}),
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) { runRcaScenario(t, sc) })
	}
}

// ---- property test --------------------------------------------------------------------

// TestRcaReportPropertyInvariants generates randomized combinations of signal
// timelines, severities, recovery evidence, lifecycle states and verdicts, and
// asserts the builder can never render an impossible report (the invariant
// suite + its own consistency gate).
func TestRcaReportPropertyInvariants(t *testing.T) {
	rng := rand.New(rand.NewSource(20260715)) // deterministic
	kinds := []struct{ kind, lane string }{
		{"probe_loss", "active_probe"},
		{"synthetic_http_5xx", "active_probe"},
		{"synthetic_dns_failure", "active_probe"},
		{"flow_volume_anomaly", "passive_flow"},
		{"bgp_adjacency_change", "control_plane"},
		{"interface_down", "control_plane"},
		{"ipsec_tunnel_status", "control_plane"},
		{"cpu_high", "device_telemetry"},
		{"lb_5xx", "device_telemetry"},
	}
	sevs := []string{"info", "warn", "high", "crit"}
	states := []string{"open", "closed", "merged"}
	verdicts := []string{"undetermined", "suspected", "confirmed"}
	base := time.Date(2026, 7, 12, 18, 0, 0, 0, time.UTC)

	for i := 0; i < 400; i++ {
		var sigs []map[string]any
		n := 1 + rng.Intn(7)
		for j := 0; j < n; j++ {
			k := kinds[rng.Intn(len(kinds))]
			ts := base.Add(time.Duration(rng.Intn(3600)) * time.Second).Format("2006-01-02 15:04:05")
			attached := rng.Intn(4) > 0
			sev := sevs[rng.Intn(len(sevs))]
			extra := map[string]any{}
			if k.lane == "active_probe" {
				extra["probe_scope"] = "customer_path"
			}
			if strings.HasSuffix(k.kind, "_status") {
				if rng.Intn(2) == 0 {
					extra["attrs"] = `{"state":"down"}`
				} else {
					extra["attrs"] = `{"state":"up"}`
					sev = "info"
					attached = false
				}
			}
			obs := fmt.Sprintf("obs-%d", rng.Intn(3))
			sigs = append(sigs, testSig(k.kind, k.lane, obs, "path", obs+"->tgt", sev, ts, attached, extra))
			// sometimes a clear
			if rng.Intn(5) == 0 {
				cts := base.Add(time.Duration(rng.Intn(3600)) * time.Second).Format("2006-01-02 15:04:05")
				sigs = append(sigs, testSig(k.kind+"_clear", k.lane, obs, "path", obs+"->tgt", "info", cts, false,
					map[string]any{"clear_ts": cts}))
			}
		}
		var hyp map[string]any
		verdict := verdicts[rng.Intn(len(verdicts))]
		if verdict != "undetermined" {
			hyp = testHyp("sig.ent.cloud.ipsec-tunnel-down", rng.Float64(), verdict,
				[]string{"ipsec_tunnel_status"}, nil, nil,
				[]string{"netops", "isp", "app_team", "cloud_provider"}[rng.Intn(4)], rng.Intn(6) == 0)
		}
		meta := testMeta(states[rng.Intn(len(states))], verdict, "sig.ent.cloud.ipsec-tunnel-down", hyp)
		rep := buildRcaReport(rcaReportInput{
			ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Meta: meta, Signals: sigs,
			Policy: defaultIncidentPolicy("t1"), Now: rcaTestNow,
		})
		assertRcaInvariants(t, rep)
	}
}
