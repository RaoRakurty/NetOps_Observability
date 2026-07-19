package main

// rca_fixtures_phase1_test.go — the postmortem spec's named regression
// fixtures (spec "Regression fixtures", owner 2026-07-19):
//
//   P-3335CF — an ACTIVE PRODUCTION incident: synthetic impact confirmed,
//              real-user impact unknown. It stays an OPERATIONAL ASSESSMENT
//              while active/unpromoted: no lessons-learned editing, impact
//              provenance shows synthetic measured + real-user "not measured".
//   P-D96E4C — a VALIDATION scenario: class = validation assessment,
//              watermarked, and NEVER rendered as a production postmortem —
//              even if a human promotes it.
//
// Both fixtures snapshot their full report JSON under testdata/ so the owner
// can review the exact document shape (spec: no deploy until the semantic
// tests and report snapshots are owner-reviewed). Regenerate deliberately with
// RCA_UPDATE_SNAPSHOTS=1.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureSnapshot compares the report's canonical JSON against the stored
// snapshot; a missing snapshot (or RCA_UPDATE_SNAPSHOTS=1) writes it.
func fixtureSnapshot(t *testing.T, name string, rep rcaReport) {
	t.Helper()
	got, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", name)
	if os.Getenv("RCA_UPDATE_SNAPSHOTS") == "1" {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("write snapshot: %v", err)
		}
		t.Logf("snapshot updated: %s", path)
		return
	}
	want, err := os.ReadFile(path) // #nosec G304 -- fixed testdata path
	if os.IsNotExist(err) {
		if werr := os.WriteFile(path, got, 0o600); werr != nil {
			t.Fatalf("write initial snapshot: %v", werr)
		}
		t.Logf("initial snapshot written for owner review: %s", path)
		return
	}
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("report JSON drifted from the owner-reviewed snapshot %s.\nIf the change is intentional, regenerate with RCA_UPDATE_SNAPSHOTS=1 and have the owner re-review.", path)
	}
}

// ---- P-3335CF ------------------------------------------------------------------

// The correlation id whose display id is P-3335CF (problemDisplayID = first
// six hex characters, uppercased).
const fixtureP3335CFID = "3335cfaa-1111-4222-8333-000000000001"

func buildFixtureP3335CF(t *testing.T) rcaReport {
	t.Helper()
	meta := testMeta("open", "suspected", "sig.ent.app.customer-path-degraded",
		testHyp("sig.ent.app.customer-path-degraded", 0.55, "suspected",
			[]string{"synthetic_http_failure", "probe_loss"},
			[]string{"flow_volume_anomaly"},
			[]string{"single modality class (active_probe); need >=2"}, "app_team", false))
	sigs := []map[string]any{
		testSig("synthetic_http_failure", "active_probe", "prober-fra", "app", "crm-portal", "high", "2026-07-12 18:12:00", true,
			map[string]any{"probe_scope": "customer_path"}),
		testSig("probe_loss", "active_probe", "prober-fra", "path", "prober-fra->crm-portal", "high", "2026-07-12 18:13:30", true,
			map[string]any{"probe_scope": "customer_path"}),
		testSig("synthetic_http_failure", "active_probe", "prober-fra", "app", "crm-portal", "high", "2026-07-12 18:16:00", true,
			map[string]any{"probe_scope": "customer_path"}),
	}
	rep := buildRcaReport(rcaReportInput{
		ID: fixtureP3335CFID, Meta: meta, Signals: sigs,
		Policy: defaultIncidentPolicy("t1"), Now: rcaTestNow,
	})
	return rep
}

func TestFixtureP3335CFStaysOperationalAssessmentWhileActive(t *testing.T) {
	rep := buildFixtureP3335CF(t)

	if rep.DisplayID != "P-3335CF" {
		t.Fatalf("display id = %q, want P-3335CF", rep.DisplayID)
	}
	// Active production incident, unpromoted → operational assessment.
	if rep.States.Incident != "active" {
		t.Fatalf("incident = %q, want active", rep.States.Incident)
	}
	if rep.Validation {
		t.Fatal("P-3335CF is a production case, never a validation scenario")
	}
	if rep.Maturity.Class != rcaClassOperational {
		t.Fatalf("class = %q, want operational_assessment (spec: stays operational while active)", rep.Maturity.Class)
	}
	if rep.Promotion.Promoted {
		t.Fatalf("unpromoted candidate reported as promoted: %+v", rep.Promotion)
	}
	// No lessons-learned editing on an operational assessment.
	if rep.LessonsLearned.Editable {
		t.Fatal("lessons-learned editing must be closed on an operational assessment")
	}
	withheld := strings.Join(rep.Maturity.WithheldSections, ",")
	if !strings.Contains(withheld, "lessons_learned") {
		t.Fatalf("lessons_learned must be withheld: %v", rep.Maturity.WithheldSections)
	}

	// Synthetic impact confirmed; real-user impact unknown (not observable).
	if rep.States.ImpactSynthetic != "confirmed" {
		t.Fatalf("impact_synthetic = %q, want confirmed", rep.States.ImpactSynthetic)
	}
	if rep.States.ImpactRealUser != "not_observable" {
		t.Fatalf("impact_real_user = %q, want not_observable (unknown — no real-traffic telemetry)", rep.States.ImpactRealUser)
	}

	// Impact provenance: synthetic measured, real-user "not measured" (never
	// derived from the synthetic failures).
	syn := provMeasure(t, rep.ImpactProvenance, "synthetic_failure_rate")
	if syn.Status != impactMeasured || syn.Value == nil || *syn.Value != 100 {
		t.Fatalf("synthetic measure = %+v, want measured 100%% (3 of 3 failed)", syn)
	}
	for _, key := range []string{"active_users", "sessions", "transactions", "user_minutes", "transaction_failures"} {
		m := provMeasure(t, rep.ImpactProvenance, key)
		if m.Status != impactNotMeasured || m.Value != nil {
			t.Fatalf("%s = %+v, want not_measured with no value", key, m)
		}
	}

	// Semantic separation holds: no trigger/root-cause invention.
	if rep.Semantics.Trigger.Determined || rep.Semantics.RootCause.Determined {
		t.Fatalf("semantics fabricated determinations: %+v", rep.Semantics)
	}

	fixtureSnapshot(t, "rca_phase1_p3335cf.snapshot.json", rep)
}

// ---- P-D96E4C ------------------------------------------------------------------

const fixturePD96E4CID = "d96e4caa-2222-4333-8444-000000000002"

func buildFixturePD96E4C(t *testing.T) rcaReport {
	t.Helper()
	meta := testMeta("open", "confirmed", "sig.ent.cloud.ipsec-tunnel-down",
		testHyp("sig.ent.cloud.ipsec-tunnel-down", 0.9, "confirmed",
			[]string{"ipsec_tunnel_status"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("ipsec_tunnel_status", "control_plane", "gw-lab-1", "seam", "sm-lab-1", "crit", "2026-07-12 18:00:00", true,
			map[string]any{"attrs": `{"state":"down","seam_id":"sm-lab-1","signal_purpose":"validation"}`}),
		testSig("probe_loss", "active_probe", "prober-lab", "path", "prober-lab->lab-svc", "crit", "2026-07-12 18:01:00", true,
			map[string]any{"probe_scope": "customer_path", "attrs": `{"signal_purpose":"validation"}`}),
	}
	return buildRcaReport(rcaReportInput{
		ID: fixturePD96E4CID, Meta: meta, Signals: sigs,
		Policy: defaultIncidentPolicy("t1"), Now: rcaTestNow,
	})
}

func TestFixturePD96E4CStaysValidationAssessment(t *testing.T) {
	rep := buildFixturePD96E4C(t)

	if rep.DisplayID != "P-D96E4C" {
		t.Fatalf("display id = %q, want P-D96E4C", rep.DisplayID)
	}
	if !rep.Validation {
		t.Fatal("validation scenario not detected")
	}
	if rep.Maturity.Class != rcaClassValidation || !rep.Maturity.Watermark {
		t.Fatalf("maturity = %+v, want watermarked validation_assessment", rep.Maturity)
	}
	// Never resembles a production postmortem: type + title carry the class,
	// production severity is suppressed, lessons stay closed.
	if !strings.Contains(rep.ReportType, "Validation") || !strings.Contains(rep.ReportType, "Nonproduction") {
		t.Fatalf("report type = %q must name the validation class", rep.ReportType)
	}
	for _, banned := range []string{"Root Cause Analysis", "Postmortem", "Incident Analysis"} {
		if strings.Contains(rep.ReportType, banned) {
			t.Fatalf("validation report type %q resembles a production artifact", rep.ReportType)
		}
	}
	if !strings.HasPrefix(rep.Title, "Validation scenario — ") {
		t.Fatalf("title = %q must carry the validation class", rep.Title)
	}
	if rep.States.SeverityIncident != "not_applicable" {
		t.Fatalf("severity_incident = %q, want not_applicable", rep.States.SeverityIncident)
	}
	if rep.LessonsLearned.Editable {
		t.Fatal("lessons-learned editing must be closed on a validation assessment")
	}

	// Even a manual promotion never turns it into a production postmortem.
	rec := rcaPromotionRecord{PromotedBy: "ops@acme", PromotedAt: "2026-07-18 12:00:00 UTC"}
	rep.Promotion = evaluateRcaPromotion(&rep, &rec)
	stampReportMaturity(&rep, "")
	if rep.Maturity.Class != rcaClassValidation || !rep.Maturity.Watermark || rep.LessonsLearned.Editable {
		t.Fatalf("promoted validation must stay a watermarked validation assessment: %+v", rep.Maturity)
	}

	// The rendered document carries the watermark and the class.
	html, err := renderRcaReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	if !strings.Contains(doc, "VALIDATION SCENARIO — NOT A PRODUCTION INCIDENT") {
		t.Fatal("rendered document missing the validation watermark")
	}
	if !strings.Contains(doc, "Validation incident assessment") {
		t.Fatal("rendered document missing the artifact-class line")
	}

	// Snapshot the UNPROMOTED shape (the canonical fixture state).
	fixtureSnapshot(t, "rca_phase1_pd96e4c.snapshot.json", buildFixturePD96E4C(t))
}
