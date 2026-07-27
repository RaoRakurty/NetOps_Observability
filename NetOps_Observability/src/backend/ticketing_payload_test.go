package main

import (
	"netops/backend/internal/ticketing"
	"strings"
	"testing"
)

func TestBuildCorrTicketFacts_DerivesFromViewAndSignals(t *testing.T) {
	meta := map[string]any{
		"top_hypothesis": "local-link-fault",
		"affected":       `{"devices":["edge1"],"interfaces":["edge1 Gi0/1"],"paths":["edge1->wan-r2"]}`,
		"window_start":   "2026-06-27 10:00:00",
		"window_end":     "2026-06-27 10:02:30",
	}
	sigRows := []map[string]any{
		{"attached": true, "kind": "if_oper_down", "modality_class": "device_telemetry", "severity": "crit"},
		{"attached": true, "kind": "probe_loss", "modality_class": "active_probe", "severity": "high", "probe_authority": "authoritative"},
		{"attached": false, "kind": "noise", "modality_class": "device_telemetry", "severity": "warn"},             // not attached → ignored
		{"attached": true, "kind": "if_oper_down_clear", "modality_class": "device_telemetry", "severity": "crit"}, // clear → ignored
	}
	view := rcaPathView{
		CorrObjectID: "obj-1",
		Verdict:      "confirmed",
		Confidence:   0.92,
		Internal:     false,
		Title:        "Confirmed local link fault on edge1 Gi0/1",
		Path:         rcaPath{Source: "edge1", Destination: "wan-r2"},
	}

	f := buildCorrTicketFacts(meta, sigRows, view)

	if f.Verdict != "confirmed" || f.Confidence != 0.92 || f.Internal {
		t.Fatalf("verdict/confidence/internal not passed through: %+v", f)
	}
	if f.PeakSeverity != "crit" {
		t.Fatalf("peak severity = %q want crit", f.PeakSeverity)
	}
	if f.ProbeOnly {
		t.Fatalf("ProbeOnly should be false (mixed modalities)")
	}
	if !f.HasAffectedEntity {
		t.Fatalf("expected an affected entity")
	}
	if f.AffectedScope != "edge1 → wan-r2" {
		t.Fatalf("affected scope = %q", f.AffectedScope)
	}
	if f.Signature != "local-link-fault" {
		t.Fatalf("signature = %q", f.Signature)
	}
	if got := f.PersistenceSeconds(); got != 150 {
		t.Fatalf("persistence = %ds want 150", got)
	}
}

func TestBuildCorrTicketFacts_ProbeOnlyLowAuthority(t *testing.T) {
	sigRows := []map[string]any{
		{"attached": true, "kind": "probe_loss", "modality_class": "active_probe", "severity": "high", "probe_authority": "low"},
	}
	f := buildCorrTicketFacts(map[string]any{}, sigRows, rcaPathView{Verdict: "suspected"})
	if !f.ProbeOnly || !f.LowAuthorityProbe {
		t.Fatalf("expected probe-only low-authority, got %+v", f)
	}
}

// P1.11 on the ticketing path: a single uncorroborated stream (one modality,
// one observer) never carries CRIT into the policy for an unconfirmed verdict —
// so a lone crit-labelled flow anomaly cannot satisfy suspected-requires-critical.
func TestBuildCorrTicketFacts_SingleStreamCritCapped(t *testing.T) {
	single := []map[string]any{
		{"attached": true, "kind": "flow_volume_anomaly", "modality_class": "passive_flow",
			"severity": "crit", "observer_id": "exporter-1"},
	}
	f := buildCorrTicketFacts(map[string]any{}, single, rcaPathView{Verdict: "suspected"})
	if f.PeakSeverity == "crit" {
		t.Fatalf("single uncorroborated stream kept crit: %+v", f)
	}
	dec := ticketing.EvalDecision(f, ticketing.DefaultIncidentPolicy("t_a"), nil, rcaTestNow)
	if dec.Create {
		t.Fatalf("single-stream suspected anomaly must not open a ticket: %+v", dec)
	}

	// corroborated (second modality, second observer) keeps its crit
	multi := append(single, map[string]any{
		"attached": true, "kind": "probe_loss", "modality_class": "active_probe",
		"severity": "crit", "observer_id": "prober-1", "probe_authority": "authoritative"})
	f2 := buildCorrTicketFacts(map[string]any{}, multi, rcaPathView{Verdict: "suspected"})
	if f2.PeakSeverity != "crit" {
		t.Fatalf("corroborated evidence lost its severity: %+v", f2)
	}
	// a confirmed verdict is exempt from the cap even single-stream
	f3 := buildCorrTicketFacts(map[string]any{}, single, rcaPathView{Verdict: "confirmed"})
	if f3.PeakSeverity != "crit" {
		t.Fatalf("confirmed verdict must keep evidence severity: %+v", f3)
	}
}

func TestBuildTicketPayload_ReusesRcaView(t *testing.T) {
	view := rcaPathView{
		CorrObjectID:           "obj-9",
		Verdict:                "confirmed",
		Confidence:             0.88,
		Title:                  "Confirmed local link fault on edge1 Gi0/1",
		Summary:                "Interface down corroborated by probe loss.",
		RecommendedAction:      "Dispatch to site; check edge1 Gi0/1 optics.",
		MissingEvidenceSummary: []string{"neighbor-side confirmation"},
		EvidenceSummary: map[string]any{
			"verdict_reason":  "two independent planes agree",
			"confirming_pair": []string{"if_oper_down", "probe_loss"},
		},
	}
	facts := ticketing.CorrFacts{Signature: "local-link-fault", AffectedScope: "edge1 Gi0/1"}
	pol := ticketing.DefaultIncidentPolicy("t_a")
	pol.AssignmentGroup = "NOC-L2"
	pol.DefaultImpact, pol.DefaultUrgency = 1, 1

	p := buildTicketPayload(view, facts, pol, "https://correlix.example/app")

	if p.CorrObjectID != "obj-9" || p.Verdict != "confirmed" {
		t.Fatalf("payload basics wrong: %+v", p)
	}
	if p.Title != view.Title {
		t.Fatalf("title should reuse RCA narration, got %q", p.Title)
	}
	if p.RCAURL != "https://correlix.example/app/correlations/obj-9" {
		t.Fatalf("deep link = %q", p.RCAURL)
	}
	if p.AssignmentGroup != "NOC-L2" || p.Impact != 1 || p.Urgency != 1 {
		t.Fatalf("policy fields not applied: %+v", p)
	}
	if len(p.MissingEvidence) != 1 {
		t.Fatalf("missing evidence not carried")
	}
	if len(p.EvidenceUsed) == 0 || !strings.Contains(p.EvidenceUsed[0], "two independent planes") {
		t.Fatalf("evidence-used not surfaced: %v", p.EvidenceUsed)
	}
}

func TestBuildTicketPayload_DefensiveTitleWhenBlank(t *testing.T) {
	p := buildTicketPayload(rcaPathView{Verdict: "suspected"}, ticketing.CorrFacts{AffectedScope: "leaf1"}, ticketing.DefaultIncidentPolicy("t_a"), "")
	if !strings.HasPrefix(p.Title, "Suspected") || !strings.Contains(p.Title, "leaf1") {
		t.Fatalf("defensive title = %q", p.Title)
	}
}

// TestTicketSeverityMapping pins the verdict/severity → ServiceNow impact/urgency
// escalation (operator report 2026-07-11: a CONFIRMED critical fault filed at the
// same P3 Moderate as everything else because only the policy defaults were sent).
// Policy defaults are the baseline; escalation only ever raises severity.
func TestTicketSeverityMapping(t *testing.T) {
	pol := ticketing.DefaultIncidentPolicy("t_a") // impact 2 / urgency 2
	cases := []struct {
		name, verdict, sev      string
		wantImpact, wantUrgency int
	}{
		{"confirmed critical → P1", "confirmed", "crit", 1, 1},
		{"confirmed non-critical → P2", "confirmed", "high", 2, 1},
		{"suspected keeps policy defaults", "suspected", "crit", 2, 2},
		{"undetermined keeps policy defaults", "undetermined", "warn", 2, 2},
	}
	for _, c := range cases {
		facts := ticketing.CorrFacts{PeakSeverity: c.sev}
		p := buildTicketPayload(rcaPathView{Verdict: c.verdict, Title: "x"}, facts, pol, "")
		if p.Impact != c.wantImpact || p.Urgency != c.wantUrgency {
			t.Fatalf("%s: impact/urgency = %d/%d, want %d/%d", c.name, p.Impact, p.Urgency, c.wantImpact, c.wantUrgency)
		}
	}

	// Escalation never DEMOTES an operator's stricter configuration.
	strict := ticketing.DefaultIncidentPolicy("t_a")
	strict.DefaultImpact, strict.DefaultUrgency = 1, 1
	p := buildTicketPayload(rcaPathView{Verdict: "suspected", Title: "x"}, ticketing.CorrFacts{PeakSeverity: "warn"}, strict, "")
	if p.Impact != 1 || p.Urgency != 1 {
		t.Fatalf("suspected under a 1/1 policy = %d/%d, must keep 1/1", p.Impact, p.Urgency)
	}
}

// TestTicketSeverityMapping_CustomerOverrides pins the per-policy priority
// mapping (owner request 2026-07-11): explicit per-verdict impact/urgency wins
// outright — including DEMOTING below the automatic escalation — and 0 keeps
// the automatic behavior per slot.
func TestTicketSeverityMapping_CustomerOverrides(t *testing.T) {
	pol := ticketing.DefaultIncidentPolicy("t_a")                    // defaults 2/2
	pol.ImpactConfirmedCritical, pol.UrgencyConfirmedCritical = 2, 2 // customer demotes P1→P3
	pol.ImpactConfirmed = 3                                          // partial: urgency stays automatic (1)

	i, u := ticketImpactUrgency(pol, "confirmed", "crit")
	if i != 2 || u != 2 {
		t.Fatalf("customer-demoted confirmed+crit = %d/%d, want 2/2", i, u)
	}
	i, u = ticketImpactUrgency(pol, "confirmed", "high")
	if i != 3 || u != 1 {
		t.Fatalf("confirmed with partial override = %d/%d, want 3/1 (explicit impact, automatic urgency)", i, u)
	}
	i, u = ticketImpactUrgency(pol, "suspected", "crit")
	if i != 2 || u != 2 {
		t.Fatalf("suspected always uses policy defaults = %d/%d, want 2/2", i, u)
	}
}
