// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_v2_p3e0400_test.go — the RCA document v2 regression case (plan of record
// docs/design/RCA_DOCUMENT_V2_2026-11-12.md §1/§3/§7).
//
// P-3E0400 (lab, 2026-11-12 04:50Z): cedge-60-07ae8615 raised interface metric
// anomalies on four interfaces, one CPU/memory change and one generic device
// alarm. The engine ranked "Local link fault" first with satisfied
// [if_metric_anomaly] and missing [link_state_change]; DNS, MAC flap and OSPF
// followed at 0.05 through optional clauses only. The old document was titled
// "Link state change" — an event that never happened — listed the three
// optional-only competitors as "observed / active", derived a 1 s "cadence"
// from burst polling across five entities and spoke of "end-to-end service
// checks" with no service evidence in the case.
//
// The object, its ranking blob and its edges are the captured lab rows
// (testdata/p3e0400/detail.json). The evidence slice was not captured, so it is
// RECONSTRUCTED here from the captured report's evidence summary: 6 anomalous
// observations (if_metric_anomaly ×4 on Gi3/Gi4/Tu1/Tu2, device_resource_anomaly
// ×1, device_alarm ×1 on the control-plane lane; 2 crit / 1 high / 3 warn),
// 34 device-health clears, 1 traffic-flow observation — 41 in the window. The
// clears are burst-polled (five entities within a second of each other every
// 30 s), which is what made the old lane-merged inter-arrival read 1 s.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/noclabel"
	"netops/backend/internal/ticketing"
)

const (
	p3e0400ID      = "3e0400bc-aa22-543b-95e4-1b6afa9cf75e"
	p3e0400Device  = "cedge-60-07ae8615"
	p3e0400Trigger = "eaf787e3-cc25-5575-90ed-0c2522175d21"
	p3e0400Title   = "Interface metric anomaly on cedge-60-07ae8615 (4 interfaces) — possible local link fault"
)

// p3e0400Now — the lab report's generation time.
var p3e0400Now = time.Date(2026, 11, 12, 4, 57, 15, 0, time.UTC)

func loadP3E0400Detail(t *testing.T) (map[string]any, []map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "p3e0400", "detail.json")) // #nosec G304 -- fixed testdata path
	if err != nil {
		t.Fatalf("read P-3E0400 detail: %v", err)
	}
	var d struct {
		Object map[string]any   `json:"object"`
		Edges  []map[string]any `json:"edges"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("decode P-3E0400 detail: %v", err)
	}
	return d.Object, d.Edges
}

func p3e0400Sig(id, kind, lane, etype, entity, sev, ts string, attached bool) map[string]any {
	s := testSig(kind, lane, p3e0400Device, etype, entity, sev, ts, attached, nil)
	if id != "" {
		s["signal_id"] = id
	}
	return s
}

func p3e0400Signals() []map[string]any {
	dev := p3e0400Device
	ifs := []string{dev + ":Gi3", dev + ":Gi4", dev + ":Tu1", dev + ":Tu2"}
	sigs := []map[string]any{
		p3e0400Sig(p3e0400Trigger, "if_metric_anomaly", "device_telemetry", "interface", ifs[0], "crit", "2026-11-12 04:50:50.589", true),
		p3e0400Sig("", "device_resource_anomaly", "device_telemetry", "device", dev, "warn", "2026-11-12 04:51:24.310", true),
		p3e0400Sig("", "if_metric_anomaly", "device_telemetry", "interface", ifs[1], "crit", "2026-11-12 04:54:20.874", true),
		p3e0400Sig("", "if_metric_anomaly", "device_telemetry", "interface", ifs[2], "high", "2026-11-12 04:54:21.001", true),
		p3e0400Sig("", "if_metric_anomaly", "device_telemetry", "interface", ifs[3], "warn", "2026-11-12 04:54:21.104", true),
		p3e0400Sig("", "device_alarm", "control_plane", "device", dev, "warn", "2026-11-12 04:54:41.391", true),
	}
	// 34 burst-polled clears: every 30 s, the five entities within ~1 s.
	base := time.Date(2026, 11, 12, 4, 51, 0, 0, time.UTC)
	entities := []struct{ etype, id, kind string }{
		{"interface", ifs[0], "if_metric_anomaly_clear"},
		{"interface", ifs[1], "if_metric_anomaly_clear"},
		{"interface", ifs[2], "if_metric_anomaly_clear"},
		{"interface", ifs[3], "if_metric_anomaly_clear"},
		{"device", dev, "device_resource_anomaly_clear"},
	}
	n := 0
	for k := 0; k < 7; k++ {
		for e, en := range entities {
			if n == 34 {
				break
			}
			ts := base.Add(time.Duration(k)*30*time.Second + time.Duration(e)*230*time.Millisecond)
			if k == 6 && e == 3 {
				ts = time.Date(2026, 11, 12, 4, 54, 36, 120_000_000, time.UTC) // the component recovery stamp
			}
			sigs = append(sigs, p3e0400Sig(fmt.Sprintf("clr-%02d", n), en.kind, "device_telemetry", en.etype, en.id, "info",
				ts.Format("2006-01-02 15:04:05.000"), false))
			n++
		}
	}
	sigs = append(sigs, testSig("flow_volume_anomaly_clear", "passive_flow", "flow-collector", "device", dev, "info",
		"2026-11-12 04:53:32.000", false, nil))
	return sigs
}

func buildFixtureP3E0400(t *testing.T) Report {
	t.Helper()
	obj, edges := loadP3E0400Detail(t)
	meta := map[string]any{}
	for _, k := range []string{"version", "state", "verdict_tier", "top_hypothesis", "top_confidence",
		"window_start", "window_end", "hypotheses", "affected", "evidence_missing", "trigger_signal", "created_at"} {
		meta[k] = obj[k]
	}
	meta["app_impact"] = "{}"
	return BuildReport(ReportInput{
		ID: p3e0400ID, Meta: meta, Signals: p3e0400Signals(), Edges: edges,
		Policy: ticketing.DefaultIncidentPolicy("t1"), Now: p3e0400Now,
	})
}

func renderP3E0400(t *testing.T) (Report, string) {
	t.Helper()
	rep := buildFixtureP3E0400(t)
	html, err := RenderReportHTML(rep)
	if err != nil {
		t.Fatalf("render P-3E0400: %v", err)
	}
	return rep, string(html)
}

// ---- §3.1 the title names the observed condition --------------------------------

func TestV2P3E0400TitleNamesTheObservedCondition(t *testing.T) {
	rep, doc := renderP3E0400(t)
	if rep.DisplayID != "P-3E0400" {
		t.Fatalf("display id = %q", rep.DisplayID)
	}
	if rep.Title != p3e0400Title {
		t.Fatalf("title = %q\nwant  %q", rep.Title, p3e0400Title)
	}
	if !strings.Contains(doc, "<h1>"+p3e0400Title+"</h1>") {
		t.Fatal("the rendered document must carry the v2 title")
	}
	if rep.Document.WhatBroke != "Interface metric anomaly on cedge-60-07ae8615 (4 interfaces)" {
		t.Fatalf("section 1 must name the observed condition, got %q", rep.Document.WhatBroke)
	}
	// The unsupported event phrase is gone from every surface of the document.
	for _, banned := range []string{"Link state change", "link state change"} {
		if strings.Contains(doc, banned) {
			t.Errorf("document still claims an unobserved %q", banned)
		}
	}
	if !strings.Contains(rep.Summary.Management, "“interface metric anomaly”") {
		t.Errorf("management summary must name the observed condition: %q", rep.Summary.Management)
	}
}

// §3.1 the other two cases: a fully satisfied signature titles with its own
// condition; MAC flap and local link fault never share a title.
func TestV2TitleRuleFullySatisfiedAndMacFlapDistinct(t *testing.T) {
	sig := func(kind, entity string, attached bool) map[string]any {
		return testSig(kind, "device_telemetry", "edge-1", "interface", entity, "high", "2026-07-12 18:12:00", attached, nil)
	}
	build := func(id, title string, satisfied, missing []string, sigs []map[string]any) Report {
		h := testHyp(id, 0.9, "suspected", satisfied, missing, nil, "netops", false)
		h["title"] = title
		return buildTestReport(t, testMeta("open", "suspected", id, h), sigs)
	}
	full := build("sig.ent.access.local-link-fault", "Local link fault",
		[]string{"link_state_change", "if_metric_anomaly"}, nil,
		[]map[string]any{sig("link_state_change", "edge-1:Gi1", true), sig("if_metric_anomaly", "edge-1:Gi1", true)})
	if full.Title != "Local link fault on edge-1 (1 interface)" {
		t.Errorf("fully satisfied title = %q", full.Title)
	}
	macPartial := build("sig.ent.access.mac-flap", "MAC flapping / move storm",
		[]string{"if_metric_anomaly|if_util_high"}, []string{"mac_flap"},
		[]map[string]any{sig("if_metric_anomaly", "edge-1:Gi1", true), sig("if_metric_anomaly", "edge-1:Gi2", true)})
	if macPartial.Title != "Interface metric anomaly on edge-1 (2 interfaces) — possible MAC address flapping" {
		t.Errorf("partial MAC flap title = %q", macPartial.Title)
	}
	macFull := build("sig.ent.access.mac-flap", "MAC flapping / move storm",
		[]string{"if_metric_anomaly|if_util_high", "mac_flap"}, nil,
		[]map[string]any{sig("mac_flap", "edge-1:Gi1", true), sig("if_metric_anomaly", "edge-1:Gi1", true)})
	if macFull.Title == full.Title || !strings.HasPrefix(macFull.Title, "MAC address flapping") {
		t.Errorf("MAC flap title %q must be distinct from local link fault %q", macFull.Title, full.Title)
	}
	for _, r := range []Report{full, macPartial, macFull} {
		if strings.Contains(r.Title, "Link state change") {
			t.Errorf("title %q uses the dropped access cascade phrase", r.Title)
		}
	}
}

// ---- §3.2/§3.3 hypothesis labels and unobserved competitors ------------------------

func TestV2P3E0400UnobservedCompetitorsAreNeverObservedOrActive(t *testing.T) {
	rep, doc := renderP3E0400(t)
	if len(rep.Hypotheses) != 4 {
		t.Fatalf("hypotheses = %d, want 4", len(rep.Hypotheses))
	}
	lead := rep.Hypotheses[0]
	if lead.Title != "Local link fault" || lead.ObservationState != "observed" || lead.CandidacyState != "active" {
		t.Fatalf("leader = %+v", lead)
	}
	want := map[string]string{
		"sig.ent.access.dns-local-resolver-failure": "Local DNS resolver failure",
		"sig.ent.access.mac-flap":                   "MAC address flapping",
		"sig.ent.access.ospf-adjacency-flap":        "OSPF adjacency flap",
	}
	for _, h := range rep.Hypotheses[1:] {
		if want[h.ID] == "" {
			t.Fatalf("unexpected competitor %s", h.ID)
		}
		if h.Title != want[h.ID] {
			t.Errorf("%s title = %q, want %q (catalog/explicit, never the cascade)", h.ID, h.Title, want[h.ID])
		}
		if h.ObservationState != "not_observed" || h.CandidacyState != rcaRoleNearestCompetitor || h.CausalRole != rcaRoleNearestCompetitor {
			t.Errorf("%s must be a nearest competitor, not observed: %+v", h.ID, h)
		}
		if h.Label != "" {
			t.Errorf("%s renders a live confidence label %q", h.ID, h.Label)
		}
	}
	for _, b := range rep.CausalChain.Branches {
		if b.EpistemicState != epistemicNotObserved || b.CausalRole != noclabel.NearestCompetitorNotObserved || len(b.Evidence) != 0 {
			t.Errorf("branch %q must read not observed with no evidence: %+v", b.Title, b)
		}
	}
	for _, o := range rep.Document.Others {
		if !strings.HasPrefix(o.Why, "Not observed") {
			t.Errorf("section 8 row %q must say it was not observed: %q", o.Title, o.Why)
		}
	}
	if c := strings.Count(doc, noclabel.NearestCompetitorNotObserved); c < 3 {
		t.Errorf("the document must label each unobserved competitor (%d labels)", c)
	}
	// A nearest competitor is never the possible cause.
	if rep.RootCause.PossibleCause == "" || strings.Contains(rep.RootCause.PossibleCause, "DNS") {
		t.Errorf("possible cause = %q", rep.RootCause.PossibleCause)
	}
	if rep.Document.Cause.Phrase != "Possibly because of local link fault" {
		t.Errorf("section 4 phrase = %q", rep.Document.Cause.Phrase)
	}
}

func TestV2NoRequiredClauseSatisfied(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	cases := []struct {
		name string
		h    rcaHypEntry
		want bool
	}{
		{"optional only (P-3E0400 DNS)", rcaHypEntry{Coverage: f(0.05), Satisfied: []string{"device_resource_anomaly"}, Missing: []string{"a|b", "c|d"}}, true},
		{"one of two required (P-3E0400 leader)", rcaHypEntry{Coverage: f(0.5), Satisfied: []string{"if_metric_anomaly"}, Missing: []string{"link_state_change"}}, false},
		{"fully satisfied", rcaHypEntry{Coverage: f(1), Satisfied: []string{"a", "b"}}, false},
		{"pre-coverage blob falls back to confidence", rcaHypEntry{Confidence: 0.05, Satisfied: []string{"x"}, Missing: []string{"y"}}, true},
		{"nothing satisfied at all", rcaHypEntry{Coverage: f(0), Missing: []string{"y"}}, true},
		{"contradicted rows are judged elsewhere", rcaHypEntry{Coverage: f(0.05), Contradicted: true, Missing: []string{"y"}}, false},
		{"one of nine required with a bonus is still a required hit", rcaHypEntry{Coverage: f(0.1111 + 0.05), Satisfied: []string{"a", "o"}, Missing: []string{"1", "2", "3", "4", "5", "6", "7", "8"}}, false},
	}
	for _, c := range cases {
		if got := rcaNoRequiredClauseSatisfied(c.h); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// ---- §3.4 one localisation sentence ------------------------------------------------

func TestV2P3E0400LocalisationSentenceEverywhere(t *testing.T) {
	rep, doc := renderP3E0400(t)
	want := noclabel.LocalisationSentence(p3e0400Device, false)
	if rep.FaultLocalization.Statement != want {
		t.Errorf("fault localisation = %q, want %q", rep.FaultLocalization.Statement, want)
	}
	if rep.AtAGlance.Where != want {
		t.Errorf("at a glance = %q, want %q", rep.AtAGlance.Where, want)
	}
	if !strings.Contains(doc, want) {
		t.Error("the document must state the localisation sentence")
	}
	if strings.Contains(doc, "not path-shaped") {
		t.Error("the document must never say the object is not path-shaped")
	}
}

// ---- §3.5 detection lag ----------------------------------------------------------------

func TestV2DetectionLagFromVersionOneCreatedAt(t *testing.T) {
	base := func() map[string]any {
		m := testMeta("open", "suspected", "sig.ent.app.customer-path-degraded",
			testHyp("sig.ent.app.customer-path-degraded", 0.55, "suspected",
				[]string{"synthetic_http_failure"}, nil, nil, "app_team", false))
		return m
	}
	trig := testSig("synthetic_http_failure", "active_probe", "prober-fra", "app", "crm-portal", "high", "2026-07-12 18:12:00", true,
		map[string]any{"probe_scope": "customer_path"})
	sigs := []map[string]any{trig}
	ms := func(rep Report, key string) *rcaDetectionMilestone {
		for i := range rep.Semantics.Milestones {
			if rep.Semantics.Milestones[i].Key == key {
				return &rep.Semantics.Milestones[i]
			}
		}
		return nil
	}

	// created_at loaded → detection milestone + lag
	m := base()
	m["trigger_signal"] = trig["signal_id"]
	m["first_version_created_at"] = "2026-07-12T18:13:05.400Z"
	rep := buildTestReport(t, m, sigs)
	det := ms(rep, msFirstDetection)
	if det == nil || det.TS != "2026-07-12 18:13:05 UTC" || !strings.Contains(det.SourceLineage, "version 1") {
		t.Fatalf("detection milestone = %+v", det)
	}
	if len(rep.Semantics.Comparisons) != 1 || rep.Semantics.Comparisons[0].DurationMS != 65_000 {
		t.Fatalf("detection lag = %+v, want 1m05s", rep.Semantics.Comparisons)
	}
	// the trigger is the case-opening observation, never the detection
	if tr := rep.Semantics.TriggeringObservation; tr == nil || tr.Key != msCaseOpeningObservation ||
		!strings.Contains(tr.SourceLineage, "also the earliest attached anomalous observation") {
		t.Fatalf("triggering observation = %+v", tr)
	}
	if lbl := ms(rep, msFirstCredibleFailure).Label; lbl != "Earliest attached anomalous observation (detector onset, not fault onset)" {
		t.Errorf("relabel = %q", lbl)
	}

	// identical stamps → the same observation: the pair is omitted
	m = base()
	m["first_version_created_at"] = "2026-07-12 18:12:00.000"
	if rep := buildTestReport(t, m, sigs); len(rep.Semantics.Comparisons) != 0 {
		t.Fatalf("a 0 s lag between one observation and itself must be omitted: %+v", rep.Semantics.Comparisons)
	}

	// not loaded / epoch / later version without the field → absent, never the trigger
	for name, v := range map[string]any{"absent": nil, "epoch": "1970-01-01T00:00:00.000Z", "empty": ""} {
		m = base()
		m["trigger_signal"] = trig["signal_id"]
		if v != nil {
			m["first_version_created_at"] = v
		}
		m["created_at"] = "2026-07-12T18:20:00Z" // version 3's own stamp is not version 1's
		rep := buildTestReport(t, m, sigs)
		if ms(rep, msFirstDetection) != nil || len(rep.Semantics.Comparisons) != 0 {
			t.Errorf("%s: detection must stay absent: %+v", name, rep.Semantics.Milestones)
		}
	}
	// a version-1 row IS the creation
	m = base()
	m["version"] = float64(1)
	m["created_at"] = "2026-07-12T18:12:40Z"
	if det := ms(buildTestReport(t, m, sigs), msFirstDetection); det == nil || det.TS != "2026-07-12 18:12:40 UTC" {
		t.Fatalf("version-1 created_at must be the detection: %+v", det)
	}
}

// ---- §3.6 coverage cadence ------------------------------------------------------------

func TestV2P3E0400CoverageCadenceIsPerSeries(t *testing.T) {
	rep := buildFixtureP3E0400(t)
	var dev, cp *rcaEvidenceLane
	for i := range rep.Coverage {
		switch rep.Coverage[i].Class {
		case "device_telemetry":
			dev = &rep.Coverage[i]
		case "control_plane":
			cp = &rep.Coverage[i]
		}
	}
	if dev == nil || dev.Assessment == nil || cp == nil {
		t.Fatalf("coverage lanes missing: %+v", rep.Coverage)
	}
	a := dev.Assessment
	if a.CadenceSource != cadenceFromSeries || a.ExpectedCadence != "30s" {
		t.Fatalf("cadence = %q from %q, want 30s per_series (burst polling must not read 1 s)", a.ExpectedCadence, a.CadenceSource)
	}
	if len(a.InternalGaps) != 0 || a.InternalGapTotal != "" {
		t.Fatalf("burst polling produced fake internal gaps: %+v", a.InternalGaps)
	}
	if a.Quality == qualityMinimal || a.Quality == qualityPartial {
		t.Fatalf("a 30 s series covering the window is not %q", a.Quality)
	}
	// §3.7: the control-plane lane carried only a device alarm.
	if cp.Label != "Device alarms" {
		t.Errorf("control-plane lane label = %q, want Device alarms", cp.Label)
	}
	for _, s := range rep.Evidence.Symptoms {
		if s.Kind == "device_alarm" && s.Source == "Routing & link events" {
			t.Error("a device alarm must not be presented as a routing & link event")
		}
	}
	if !strings.Contains(rep.Summary.WhySuspected, "not evidence for the leading explanation (Local link fault)") ||
		!strings.Contains(rep.Summary.WhySuspected, "device alarm") {
		t.Errorf("the report must say the alarm is not a witness: %q", rep.Summary.WhySuspected)
	}
}

func TestV2CoverageMultiEntityInterArrivalMakesNoGapClaim(t *testing.T) {
	ws := time.Date(2026, 11, 12, 4, 50, 0, 0, time.UTC)
	we := ws.Add(4 * time.Minute)
	var obs []time.Time
	var series [][]time.Time
	for e := 0; e < 5; e++ {
		var s []time.Time
		for k := 0; k <= 8; k++ {
			ts := ws.Add(time.Duration(k)*30*time.Second + time.Duration(e)*200*time.Millisecond)
			s = append(s, ts)
			obs = append(obs, ts)
		}
		series = append(series, s)
	}
	eng := newCoverageEngine(nil)
	in := LaneCoverageInput{Class: "device_telemetry", WindowStart: ws, WindowEnd: we, Observations: obs, Series: series, TotalCount: len(obs)}
	a := eng.Assess("t1", in)
	if a.CadenceSource != cadenceFromSeries || a.ExpectedCadence != "30s" || len(a.InternalGaps) != 0 {
		t.Fatalf("per-series cadence = %q/%q gaps=%v", a.ExpectedCadence, a.CadenceSource, a.InternalGaps)
	}
	// The same arrivals read as ONE merged series (the old behaviour) invent a
	// 200 ms cadence and a forest of gaps — the defect §3.6 removes.
	merged := eng.Assess("t1", LaneCoverageInput{Class: "device_telemetry", WindowStart: ws, WindowEnd: we, Observations: obs, TotalCount: len(obs)})
	if len(merged.InternalGaps) == 0 {
		t.Fatal("fixture sanity: the merged series should show the fake gaps")
	}

	// Series too short for an inter-arrival → cadence unknown, and NO gap,
	// partial or minimal claim.
	short := eng.Assess("t1", LaneCoverageInput{
		Class: "device_telemetry", WindowStart: ws, WindowEnd: we,
		Observations: []time.Time{ws, ws.Add(time.Second), ws.Add(3 * time.Minute)},
		Series:       [][]time.Time{{ws, ws.Add(3 * time.Minute)}, {ws.Add(time.Second)}},
		TotalCount:   3,
	})
	if short.CadenceKnown || short.Quality != qualityUnknown || short.RatioKnown ||
		len(short.InternalGaps) != 0 || short.LeadingGap != "" || short.TrailingGap != "" || short.MissingInterval != "" {
		t.Fatalf("unknown cadence must make no interval claim: %+v", short)
	}
	if got := short.legacyCoverage(); got != "unknown" {
		t.Errorf("legacy coverage = %q, want unknown (data present, cadence unknown)", got)
	}
	if got := short.legacyState(false); got != "inconclusive" {
		t.Errorf("legacy state = %q, want inconclusive — the lane HAS data", got)
	}
	if f := rcaCoverageFinding(3, 0, short); !strings.Contains(f, "not known") || strings.Contains(f, "Missing interval") {
		t.Errorf("finding = %q", f)
	}
}

// ---- §3.8 service wording -------------------------------------------------------------

func TestV2P3E0400NoServiceWordingWithoutServiceEvidence(t *testing.T) {
	rep, doc := renderP3E0400(t)
	for _, banned := range []string{"monitored service", "end-to-end service checks", "end-to-end evidence continued", "Validate end-to-end service recovery"} {
		if strings.Contains(doc, banned) {
			t.Errorf("document claims service scope without service evidence: %q", banned)
		}
	}
	if !strings.Contains(rep.Summary.Management, "affecting cedge-60-07ae8615") {
		t.Errorf("subject must be the device, got %q", rep.Summary.Management)
	}
	if rep.States.RecoveryService.State != "not_applicable" {
		t.Fatalf("fixture: no service-scope evidence expected, got %+v", rep.States.RecoveryService)
	}
}

func TestV2RecoveryWordingByScope(t *testing.T) {
	t0 := time.Date(2026, 7, 12, 18, 0, 0, 0, time.UTC)
	ts := func(m int) string { return t0.Add(time.Duration(m) * time.Minute).Format("2006-01-02 15:04:05") }
	comp := func(kind, at string) map[string]any {
		return testSig(kind, "device_telemetry", "edge-1", "interface", "edge-1:Gi1", "high", at, !strings.HasSuffix(kind, "_clear"), nil)
	}
	// component-only: anomaly, clear, anomaly again
	ra := ReconcileRecovery(
		[]map[string]any{comp("if_errors", ts(0)), comp("if_errors", ts(5))},
		[]map[string]any{comp("if_errors_clear", ts(3))})
	phases := BuildIncidentPhases(t0, ra, "")
	var residual string
	for _, p := range phases {
		if p.Type == "residual_degradation" {
			residual = p.Summary
		}
	}
	if residual == "" || strings.Contains(residual, "end-to-end") || !strings.Contains(residual, "same component") {
		t.Fatalf("component-only residual wording = %q", residual)
	}
	acts := planActions(rcaActionInput{Analysis: "suspected", Incident: "active", Residual: true, ServiceScope: false})
	for _, a := range acts {
		if strings.Contains(a.Action, "end-to-end") {
			t.Errorf("component-only residual action speaks of end-to-end: %q", a.Action)
		}
	}
	// with service-scope evidence the end-to-end wording is the honest one
	acts = planActions(rcaActionInput{Analysis: "suspected", Incident: "active", Residual: true, ServiceScope: true})
	found := false
	for _, a := range acts {
		found = found || strings.Contains(a.Action, "Validate end-to-end service recovery")
	}
	if !found {
		t.Error("with service-scope evidence the end-to-end validation action must remain")
	}
}

// ---- §4 the NOC document on P-3E0400 ----------------------------------------------------

func TestV2P3E0400TenSectionsAndReadingGuide(t *testing.T) {
	_, doc := renderP3E0400(t)
	pos := 0
	for _, band := range rcaPhase2SectionBands {
		i := strings.Index(doc[pos:], band)
		if i < 0 {
			t.Fatalf("section %q missing or out of order", band)
		}
		pos += i + len(band)
	}
	// section 6 states where the evidence concentrates even without a path
	sec6 := doc[strings.Index(doc, "6 · Where the break is"):strings.Index(doc, "7 · Background")]
	if !strings.Contains(sec6, noclabel.LocalisationSentence(p3e0400Device, false)) {
		t.Errorf("section 6 must carry the localisation sentence:\n%s", sec6)
	}
	// no engine jargon in the operator document
	if m := regexp.MustCompile(`sig\.ent\.`).FindString(doc); m != "" {
		t.Errorf("raw template id in the document: %q", m)
	}
}

// Section 6 renders WS-A's TopologyContext partial when the HTTP layer attaches
// one; until then the spine fallback stays.
func TestV2Section6UsesTopologyContextWhenAttached(t *testing.T) {
	rep := buildFixtureP3E0400(t)
	rep.TopologyContext = &TopologyContext{State: "device_only", Reason: "Device known; no neighbour data was returned."}
	html, err := RenderReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	sec6 := doc[strings.Index(doc, "6 · Where the break is"):strings.Index(doc, "7 · Background")]
	if !strings.Contains(sec6, `data-state="device_only"`) || !strings.Contains(sec6, "no neighbour data") {
		t.Fatalf("section 6 must render the topologyContext partial:\n%s", sec6)
	}
}

// D3 on P-3E0400: suspected, one witness, no measurement pair → no automatic
// RCA document; and a background-only case never promotes whatever its counts.
func TestV2PromotionP3E0400AndBackgroundOnly(t *testing.T) {
	rep := buildFixtureP3E0400(t)
	if st := EvaluatePromotion(&rep, nil); st.Promoted {
		t.Fatalf("P-3E0400 must not auto-promote: %+v", st)
	}
	bg := promoBase()
	bg.Eligibility.CausalHeadline, bg.Eligibility.ContextOnly = false, true
	bg.Eligibility.ControllerOrHub, bg.Eligibility.Sites = true, MultiSiteMin+3
	bg.SetRecurrence(RepeatOffenderMin + 5)
	bg.States = ReportStates{Analysis: "confirmed", Impact: "confirmed"}
	bg.ConfirmingPair = rcaConfirmingPair{Observers: []string{"a", "b"}, Measured: true}
	bg.Times.DurationMS = (20 * time.Minute).Milliseconds()
	if st := EvaluatePromotion(&bg, nil); st.Promoted {
		t.Fatalf("a background-only case must never promote: %+v", st)
	}
}

// ---- golden ---------------------------------------------------------------------------

func TestV2P3E0400DocumentSnapshot(t *testing.T) {
	_, doc := renderP3E0400(t)
	fixtureSnapshotBytes(t, filepath.Join("p3e0400", "rca_v2.html.snapshot"), []byte(doc))
}
