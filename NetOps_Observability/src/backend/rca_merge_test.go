package main

// rca_merge_test.go — merged-incident lifecycle scenarios (P1). These extend the
// shared table-driven harness (runRcaScenario / assertRcaInvariants) — the merge
// rows are the same kind of fact-set as every other issue family, never special
// cased. Generic: no P-E22C5E ids, ips, timestamps or seam names.

import (
	"strings"
	"testing"
)

// merged and superseded are first-class canonical lifecycle states (never
// free-text) — the vocabulary the report derives from.
func TestMergedIsCanonicalLifecycle(t *testing.T) {
	want := map[string]bool{"merged": false, "superseded": false}
	for _, s := range rcaCanonicalLifecycles {
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for s, found := range want {
		if !found {
			t.Fatalf("%q must be a canonical lifecycle state", s)
		}
	}
}

// mergedIpsecResidualSigs — a component (IPsec) recovery followed by end-to-end
// checks that keep failing: component recovered, service NOT recovered. The same
// shape works for any component/service pair (BGP/probe, LB/flow, …).
func mergedIpsecResidualSigs() []map[string]any {
	return []map[string]any{
		sigStatusDown("ipsec_tunnel_status", "2026-07-12 18:11:00", "lab-vpn-edge"),
		sigProbeLoss("2026-07-12 18:12:00", "crit", "lan-vantage-1", "10.60.10.10"),
		sigProbeLoss("2026-07-12 18:13:30", "crit", "lan-vantage-1", "10.60.10.10"),
		sigStatusUp("ipsec_tunnel_status", "2026-07-12 18:13:00", "lab-vpn-edge"),
		sigProbeLoss("2026-07-12 18:14:00", "crit", "lan-vantage-1", "10.60.10.10"),
	}
}

func mergedMeta() map[string]any {
	meta := testMeta("merged", "confirmed", "sig.ent.cloud.ipsec-tunnel-down",
		testHyp("sig.ent.cloud.ipsec-tunnel-down", 0.9, "confirmed",
			[]string{"ipsec_tunnel_status", "probe_loss"}, nil, nil, "netops", false))
	meta["merged_into"] = "11112222-3333-4444-5555-666677778888"
	return meta
}

// (Test 1+2) component recovered while service still failing, AND the source was
// merged: lifecycle=merged (not closed), service recovery failed validation, the
// surviving incident is required and authoritative, and the source runs no
// independent monitoring/ticket/escalation side effects.
func TestScenarioMergedSourceLifecycle(t *testing.T) {
	sc := rcaScenario{
		name:        "merged source — component recovered, service failing",
		meta:        mergedMeta(),
		sigs:        mergedIpsecResidualSigs(),
		survivingID: "11112222-3333-4444-5555-666677778888",
		incident:    "merged",
		recovery:    "failed_validation", // service scope failed — never "not applicable"
		recoveredAt: "",                  // no incident-level recovery captured
		ticketState: "transferred_to_survivor",
		reportType:  "Incident Analysis — Merged / Fault Confirmed",
		// the merged source issues no independent restoration/diagnostic actions
		firstActionOpP: "P2",
		actionMustNot:  []string{"IKE", "Validate end-to-end service recovery", "Inspect the most recent failed check"},
		mgmtMustContain: []string{
			"merged into incident P-111122",
			"surviving incident owns lifecycle, monitoring, ticketing and restoration actions",
		},
		custom: func(t *testing.T, rep rcaReport) {
			if rep.States.Lifecycle != "merged" {
				t.Fatalf("lifecycle = %q, want merged", rep.States.Lifecycle)
			}
			if rep.Merge == nil {
				t.Fatal("merged report must carry a merge record")
			}
			if rep.Merge.SurvivingIncidentID == "" || rep.Merge.SurvivingDisplayID != "P-111122" {
				t.Fatalf("surviving incident not resolved: %+v", rep.Merge)
			}
			if rep.Merge.IsAuthoritative {
				t.Fatal("merged source must NOT be authoritative")
			}
			if !rep.Merge.SideEffectsTransferred ||
				rep.Merge.TicketResponsibility != "surviving_incident" ||
				rep.Merge.MonitoringResponsibility != "surviving_incident" ||
				rep.Merge.EscalationResponsibility != "surviving_incident" ||
				rep.Merge.ActionResponsibility != "surviving_incident" {
				t.Fatalf("side effects not fully transferred: %+v", rep.Merge)
			}
			// recovery must remain the reconciled assessment, not "not_applicable"
			if rep.States.Recovery == "not_applicable" {
				t.Fatal("merged source must keep its reconciled recovery, not not_applicable")
			}
			if rep.States.RecoveryComponent.State != "explicitly_confirmed" {
				t.Fatalf("component recovery = %q, want explicitly_confirmed", rep.States.RecoveryComponent.State)
			}
			// no independent side effects
			if rep.States.Monitoring == "active" {
				t.Fatal("merged source must not run its own monitoring window")
			}
			if rep.Decision.EscalationState == "triggered" {
				t.Fatalf("merged source must not trigger its own escalation: %q", rep.Decision.EscalationState)
			}
			if rep.Decision.TicketRecommended != "transferred" {
				t.Fatalf("ticket recommendation = %q, want transferred", rep.Decision.TicketRecommended)
			}
			// NOC quick-read leads with the merge
			var incidentState, ticket string
			for _, kv := range rep.Summary.Noc {
				switch kv.K {
				case "Incident state":
					incidentState = kv.V
				case "Ticket":
					ticket = kv.V
				}
			}
			if !strings.Contains(incidentState, "Merged into P-111122") {
				t.Fatalf("NOC incident state = %q", incidentState)
			}
			if !strings.Contains(ticket, "Managed by surviving incident P-111122") {
				t.Fatalf("NOC ticket = %q", ticket)
			}
			// exactly one coordination action, no restoration P1
			for _, a := range rep.Actions {
				if a.OperationalPriority == "P1" {
					t.Fatalf("merged source must not carry a P1 action: %+v", a)
				}
			}
		},
	}
	runRcaScenario(t, sc)
}

// (Test 3) merged source whose survivor cannot be resolved → the quality gate
// raises a P1 error and the document is downgraded to a draft (no final PDF).
func TestScenarioMergedMissingSurvivor(t *testing.T) {
	meta := testMeta("merged", "confirmed", "sig.ent.cloud.ipsec-tunnel-down",
		testHyp("sig.ent.cloud.ipsec-tunnel-down", 0.9, "confirmed",
			[]string{"ipsec_tunnel_status", "probe_loss"}, nil, nil, "netops", false))
	// no merged_into, no resolved survivor
	rep := buildRcaReport(rcaReportInput{
		ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Meta: meta, Signals: mergedIpsecResidualSigs(),
		Policy: defaultIncidentPolicy("t1"), Now: rcaTestNow,
	})
	if rep.States.Incident != "merged" {
		t.Fatalf("incident = %q, want merged", rep.States.Incident)
	}
	if rep.Quality.Passed {
		t.Fatal("a merged source with an unresolved survivor must fail the quality gate")
	}
	found := false
	for _, e := range rep.Quality.Errors {
		if e.Code == "merged_without_surviving_incident" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing P1 error merged_without_surviving_incident: %+v", rep.Quality.Errors)
	}
	if !strings.HasPrefix(rep.ReportType, "Draft") {
		t.Fatalf("contradictory merged report must downgrade to draft, got %q", rep.ReportType)
	}
}

// (Test 4) after a merge the ticket is explicitly transferred — never left as an
// ambiguous "Not opened".
func TestScenarioMergedTicketTransfer(t *testing.T) {
	sc := rcaScenario{
		name:        "merged ticket transfer",
		meta:        mergedMeta(),
		sigs:        mergedIpsecResidualSigs(),
		survivingID: "11112222-3333-4444-5555-666677778888",
		ticketState: "transferred_to_survivor",
		custom: func(t *testing.T, rep rcaReport) {
			if rep.States.Ticket == "not_opened" {
				t.Fatal("merged source ticket must not read not_opened")
			}
			if !strings.Contains(rep.Decision.TicketExecutionNote, "surviving incident P-111122") {
				t.Fatalf("ticket execution note = %q", rep.Decision.TicketExecutionNote)
			}
		},
	}
	runRcaScenario(t, sc)
}
