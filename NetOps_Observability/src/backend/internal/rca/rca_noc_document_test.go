// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_noc_document_test.go — the NOC RCA document (owner decisions D1/D3/D4,
// 2026-11-11, from the Fable review of P-424934). Pins:
//
//   - the four fixed phrases, from the engine tier/label only;
//   - a background story (standing posture/exposure + a fault) is never the
//     headline, never impact, never confirmed, and renders in its own band;
//   - impact sentences read the impact axes only — never the verdict;
//   - security / management_plane never reach an operator as raw tokens;
//   - the formal-document triggers: real outage (measurement pair), repeat
//     offender, multi-site controller/hub — and the refusals (background-only,
//     never-established peer, a security/controller confirming pair);
//   - the PDF renders the ten sections, the background band and the guide.

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/ticketing"
)

// metaWith builds an object row whose blob carries several ranked hypotheses.
func metaWith(state, verdict, top string, hyps ...map[string]any) map[string]any {
	blob, _ := json.Marshal(map[string]any{"ranking": map[string]any{"hypotheses": hyps}})
	return map[string]any{
		"version": float64(3), "state": state, "verdict_tier": verdict,
		"top_hypothesis": top, "top_confidence": 1.0,
		"window_start": "2026-11-11 00:00:00", "window_end": "2026-11-11 00:08:00",
		"hypotheses": string(blob), "affected": `{"devices":["cEDGE-81"],"sites":["RETAIL-WALMART"]}`,
		"app_impact": "{}", "evidence_missing": "[]", "tenant_id": "t1",
	}
}

const p424934Vmanage = "ctl-vmanage-bfa81d722501"

// p424934 — the review's case: an exposure story on top, persisted CONFIRMED on
// a security + via_controller pair; a BGP flap story (vManage only) behind it.
// withCausal=false is the background-only variant.
func p424934(t *testing.T, withCausal bool) Report {
	t.Helper()
	story := map[string]any{
		"id": "sig.ent.security.exposure-story", "confidence": 1.0, "confidence_label": "confirmed",
		"satisfied": []string{"security_exposure", "bgp_adjacency_change|link_state_change"}, "missing": []string{},
		"operator_phrase": "This device carries a known exposure and is showing a network fault at the same time — the two are on one node, not yet proven to be one cause",
		"verdict": map[string]any{
			"verdict_tier": "confirmed", "owner": "netops", "layer": "security/exposure",
			"independent_pair":   []string{p424934Vmanage, "security:netrule"},
			"trusted_modalities": []string{"control_plane", "security"},
			"modality_coverage":  []string{"control_plane", "security"},
			"observer_coverage":  []string{p424934Vmanage, "security:netrule"},
		},
	}
	bgp := map[string]any{
		"id": "sig.ent.wan-edge.bgp-peer-flap", "confidence": 1.0, "confidence_label": "suspected",
		"satisfied": []string{"bgp_adjacency_change"}, "missing": []string{"control_plane"},
		"verdict": map[string]any{
			"verdict_tier": "suspected", "owner": "netops",
			"reasons":           []string{"single modality class (control_plane); need >=2"},
			"modality_coverage": []string{"control_plane"}, "observer_coverage": []string{p424934Vmanage},
		},
	}
	hyps := []map[string]any{story}
	if withCausal {
		hyps = append(hyps, bgp)
	}
	meta := metaWith("open", "confirmed", "sig.ent.security.exposure-story", hyps...)
	ctl := map[string]any{"source": "controller", "collection_path": "via_controller", "observer_type": "controller"}
	sigs := []map[string]any{
		testSig("bgp_adjacency_change", "control_plane", p424934Vmanage, "device", "cEDGE-81", "high", "2026-11-11 00:00:30", true,
			merge(ctl, map[string]any{"attrs": `{"peer":"192.168.200.34","state":"idle","correlation_hints":{"bgp_transition_class":"never_established","bgp_transition_basis":"never seen established","bgp_peer_routerid":"unset"}}`})),
		testSig("bgp_adjacency_change", "control_plane", p424934Vmanage, "device", "cEDGE-81", "high", "2026-11-11 00:02:30", true,
			merge(ctl, map[string]any{"attrs": `{"peer":"192.168.200.34"}`})),
		testSig("security_exposure", "security", "security:netrule", "device", "cEDGE-81", "high", "2026-11-11 00:03:30", true,
			map[string]any{"source": "security", "attrs": `{"control_title":"Telnet permitted on management lines"}`}),
		testSig("security_posture", "security", "security:netrule", "device", "cEDGE-81", "high", "2026-11-11 00:03:30", true,
			map[string]any{"source": "security", "attrs": `{"control_title":"Telnet reachable from an untrusted seam"}`}),
	}
	return BuildReport(ReportInput{
		ID: "a4249340-0000-4000-8000-000000000000", Meta: meta, Signals: sigs,
		Policy: ticketing.DefaultIncidentPolicy("t1"), Now: time.Date(2026, 11, 11, 0, 30, 0, 0, time.UTC),
	})
}

func merge(a, b map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// ---- D1: P-424934 renders Possibly/Not determined, background band, no promotion

func TestNocDocumentP424934BackgroundStoryNeverConfirms(t *testing.T) {
	rep := p424934(t, true)

	if rep.States.Analysis == "confirmed" {
		t.Fatalf("a background story's gate must not confirm the headline: analysis=%s", rep.States.Analysis)
	}
	if got := rep.Document.Cause.Phrase; !strings.HasPrefix(got, "Possibly because of ") {
		t.Fatalf("phrase = %q, want Possibly because of …", got)
	}
	if strings.Contains(strings.ToLower(rep.Document.Cause.Phrase), "exposure") {
		t.Fatalf("the cause must be the network story, not the exposure: %q", rep.Document.Cause.Phrase)
	}
	for _, h := range rep.Hypotheses {
		if h.ID == "sig.ent.security.exposure-story" {
			t.Fatal("a background story is never ranked among the explanations")
		}
	}
	if strings.Contains(rep.Title, "Exposed device") || strings.Contains(rep.Document.WhatBroke, "Exposed device") {
		t.Fatalf("raw template title leaked: %q / %q", rep.Title, rep.Document.WhatBroke)
	}
	titles := map[string]bool{}
	for _, b := range rep.Background {
		titles[b.Title] = true
		if !strings.Contains(strings.ToLower(b.Detail), "background") {
			t.Errorf("background row must say it is background: %+v", b)
		}
	}
	for _, want := range []string{"Known security exposure on this device", "Telnet permitted on management lines", "Telnet reachable from an untrusted seam"} {
		if !titles[want] {
			t.Errorf("background band missing %q (have %v)", want, titles)
		}
	}
	// never impact: no axis is measured or indicated by security evidence
	for _, a := range rep.Document.WhoAffected {
		if a.Axis != "Sites" && a.State != "not measured" {
			t.Errorf("security evidence counted as impact: %+v", a)
		}
	}
	// never a definitive break, never "how we know" from the standing finding
	for _, r := range rep.Document.HowWeKnow {
		if strings.Contains(r.Text, "security") || strings.Contains(r.Text, "Security") {
			t.Errorf("a standing finding is listed as a reason the cause is believed: %q", r.Text)
		}
	}
	if rep.Document.OneWitness == "" || !strings.Contains(rep.Document.OneWitness, "vManage") {
		t.Errorf("several observations through one controller must read as one witness: %q", rep.Document.OneWitness)
	}
	// not promoted
	rep.Promotion = EvaluatePromotion(&rep, nil)
	if rep.Promotion.Promoted {
		t.Fatalf("P-424934 must never become an RCA document: %+v", rep.Promotion)
	}
	if !rep.Eligibility.NeverEstablished {
		t.Error("the vManage BGP reports classify the peer as never established")
	}
}

func TestNocDocumentBackgroundOnlyIsNotDetermined(t *testing.T) {
	rep := p424934(t, false)
	if rep.Document.Cause.Phrase != "Cause not determined" {
		t.Fatalf("background-only phrase = %q", rep.Document.Cause.Phrase)
	}
	if !rep.Eligibility.ContextOnly || rep.Eligibility.CausalHeadline {
		t.Fatalf("eligibility = %+v", rep.Eligibility)
	}
	if rep.States.Analysis == "confirmed" {
		t.Fatalf("analysis = %s", rep.States.Analysis)
	}
	// force every other criterion: it still never promotes
	rep.States.Impact, rep.States.Analysis = "confirmed", "confirmed"
	rep.ConfirmingPair.Measured = true
	rep.SetRecurrence(9)
	rep.Eligibility.ControllerOrHub, rep.Eligibility.Sites = true, 5
	if st := EvaluatePromotion(&rep, nil); st.Promoted {
		t.Fatalf("a background-only object must never promote: %+v", st)
	}
}

// The engine flag is honoured for ANY id (the contract the engine agent emits).
func TestNocDocumentContextStoryFlagIsHonoured(t *testing.T) {
	story := testHyp("sig.ent.security.future-story", 1, "confirmed", []string{"security_signal"}, nil, nil, "netops", false)
	story["context_story"] = true
	causal := testHyp("sig.ent.access.local-link-fault", 0.6, "suspected", []string{"link_state_change"}, nil, nil, "netops", false)
	meta := metaWith("open", "confirmed", "sig.ent.security.future-story", story, causal)
	rep := buildTestReport(t, meta, []map[string]any{
		testSig("link_state_change", "control_plane", "edge-1", "interface", "edge-1:Gi1", "high", "2026-11-11 00:01:00", true, nil),
	})
	if rep.States.Analysis == "confirmed" || len(rep.Background) == 0 {
		t.Fatalf("flagged story must leave the ranking: analysis=%s background=%v", rep.States.Analysis, rep.Background)
	}
	if rep.Hypotheses[0].ID != "sig.ent.access.local-link-fault" {
		t.Fatalf("headline = %s", rep.Hypotheses[0].ID)
	}
}

// ---- D4: the four phrases from the analysis --------------------------------------

func TestNocDocumentFourPhrases(t *testing.T) {
	sig := []map[string]any{
		testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:12:00", true, nil),
		testSig("if_errors", "device_telemetry", "wan-r2-snmp", "interface", "wan-r2:Gi1", "high", "2026-07-12 18:12:10", true, nil),
	}
	cases := []struct {
		verdict, label, want string
	}{
		{"confirmed", "confirmed", "Confirmed cause"},
		{"suspected", "likely", "Likely cause"},
		{"suspected", "suspected", "Possibly because of "},
		{"undetermined", "", "Cause not determined"},
	}
	for _, c := range cases {
		h := testHyp("sig.ent.wan-edge.bgp-peer-down", 0.7, c.label, []string{"bgp_adjacency_change"}, nil, nil, "netops", false)
		if c.verdict == "undetermined" {
			h = testHyp("sig.ent.wan-edge.bgp-peer-down", 0, "", nil, nil, nil, "netops", false)
		}
		rep := buildTestReport(t, testMeta("open", c.verdict, "sig.ent.wan-edge.bgp-peer-down", h), sig)
		if !strings.HasPrefix(rep.Document.Cause.Phrase, c.want) {
			t.Errorf("%s/%s → %q, want %q", c.verdict, c.label, rep.Document.Cause.Phrase, c.want)
		}
		if strings.Contains(rep.Document.Cause.Phrase, "%") {
			t.Errorf("a phrase never carries a number: %q", rep.Document.Cause.Phrase)
		}
	}
}

// ---- gap 1: impact never from the verdict -------------------------------------------

func TestNocDocumentImpactNeverFromVerdict(t *testing.T) {
	// a CONFIRMED fault (measurement pair) with no impact evidence at all
	h := testHyp("sig.ent.wan-edge.bgp-peer-down", 0.9, "confirmed", []string{"bgp_adjacency_change", "if_errors"}, nil, nil, "netops", false)
	h["verdict"].(map[string]any)["independent_pair"] = []string{"wan-r2", "wan-r2-snmp"}
	sigs := []map[string]any{
		testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:12:00", true, nil),
		testSig("if_errors", "device_telemetry", "wan-r2-snmp", "interface", "wan-r2:Gi1", "high", "2026-07-12 18:12:10", true, nil),
	}
	rep := buildTestReport(t, testMeta("open", "confirmed", "sig.ent.wan-edge.bgp-peer-down", h), sigs)
	if rep.States.Analysis != "confirmed" || !rep.ConfirmingPair.Measured {
		t.Fatalf("fixture: analysis=%s pair=%+v", rep.States.Analysis, rep.ConfirmingPair)
	}
	if strings.Contains(rep.Decision.Reason, "Customer impact and fault are confirmed") ||
		!strings.Contains(rep.Decision.Reason, "customer impact is not measured") {
		t.Fatalf("decision reason derives impact from the verdict: %q", rep.Decision.Reason)
	}
	for _, a := range rep.Document.WhoAffected {
		if (a.Axis == "Real users" || a.Axis == "Synthetic checks") && a.State != "not measured" {
			t.Fatalf("an axis was filled from the verdict: %+v", a)
		}
	}

	// a confirmed verdict whose recorded pair includes a SECURITY rule: real-user
	// evidence stays "detected", escalation stays armed
	h2 := testHyp("sig.ent.security.threat-signal-story", 0.9, "confirmed", []string{"security_signal", "lb_5xx"}, nil, nil, "netops", false)
	h2["verdict"].(map[string]any)["independent_pair"] = []string{"security:ids", "alb-1"}
	h2["verdict"].(map[string]any)["trusted_modalities"] = []string{"security", "device_telemetry"}
	sigs2 := []map[string]any{
		testSig("security_signal", "security", "security:ids", "device", "edge-1", "high", "2026-07-12 18:12:00", true, nil),
		testSig("lb_5xx", "device_telemetry", "alb-1", "app", "portal", "high", "2026-07-12 18:12:30", true, nil),
	}
	rep2 := buildTestReport(t, testMeta("open", "confirmed", "sig.ent.security.threat-signal-story", h2), sigs2)
	if !rep2.ConfirmingPair.Refutes() {
		t.Fatalf("a security member must refute the measurement pair: %+v", rep2.ConfirmingPair)
	}
	if rep2.States.ImpactRealUser == "confirmed" || rep2.States.Impact == "confirmed" {
		t.Fatalf("a security-backed verdict upgraded real-user impact: %s/%s", rep2.States.ImpactRealUser, rep2.States.Impact)
	}
	if rep2.Decision.EscalationState == "triggered" {
		t.Fatalf("escalation triggered on a security-backed verdict: %+v", rep2.Decision)
	}
}

// ---- gap 4: security labels -----------------------------------------------------------

func TestNocDocumentSecurityTokensNeverRaw(t *testing.T) {
	got := FriendlyReasons([]string{
		"single modality class (security); need >=2",
		"single modality class (management_plane); need >=2",
		"weak support from security and management_plane evidence",
	})
	for _, r := range got {
		if strings.Contains(r, "management_plane") || strings.Contains(r, "(security)") || strings.Contains(r, " security and") {
			t.Errorf("raw token reached the operator: %q", r)
		}
	}
	if !strings.Contains(got[0], "a security rule") || !strings.Contains(got[1], "controller") {
		t.Errorf("plain labels missing: %v", got)
	}
	if FriendlyReasons([]string{"security_exposure seen"})[0] != "security_exposure seen" {
		t.Error("a token is rewritten only as a whole word")
	}
	if rcaLaneLabel["security"] == "" {
		t.Error("the security lane needs a plain label")
	}
	if rcaProblemFor("sig.ent.security.exposure-story", "") == "" || rcaProblemFor("sig.ent.security.fw-policy-drop", "") == "" {
		t.Error("security templates need a problem statement")
	}
}

// ---- gap 5: standing findings leave the detailed timeline unless dated ---------------

func TestNocDocumentStandingFindingsOutOfTimeline(t *testing.T) {
	// The posture finding is the EARLIEST observation and the trigger — undated,
	// it still never dates the incident and never enters the timeline.
	h := testHyp("sig.ent.access.local-link-fault", 0.6, "suspected", []string{"link_state_change"}, nil, nil, "netops", false)
	build := func(postureAttrs string) Report {
		meta := testMeta("open", "suspected", "sig.ent.access.local-link-fault", h)
		meta["trigger_signal"] = "s-security_posture-2026-07-12 18:11:00"
		return buildTestReport(t, meta, []map[string]any{
			testSig("security_posture", "security", "security:netrule", "device", "edge-1", "high", "2026-07-12 18:11:00", true,
				map[string]any{"attrs": postureAttrs}),
			testSig("link_state_change", "control_plane", "edge-1", "interface", "edge-1:Gi1", "high", "2026-07-12 18:12:30", true, nil),
		})
	}
	rep := build(`{"control_title":"Telnet allowed"}`)
	if rep.Times.FirstObserved != "2026-07-12 18:12:30 UTC" {
		t.Fatalf("an undated standing finding dated the incident: first observed %q", rep.Times.FirstObserved)
	}
	for _, e := range rep.Timeline {
		if strings.Contains(strings.ToLower(e.Event+e.Source), "security") || strings.Contains(e.TS, "18:11:00") {
			t.Fatalf("an undated standing finding entered the timeline: %+v", e)
		}
	}
	found := false
	for _, b := range rep.Background {
		if b.Title == "Telnet allowed" && b.FirstSeen == "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the undated finding belongs in the background band: %+v", rep.Background)
	}

	// a DATED finding is an event: it dates the incident and carries its time
	dated := build(`{"control_title":"Telnet allowed","first_seen":"2026-07-12 18:10:00"}`)
	if dated.Times.FirstObserved != "2026-07-12 18:11:00 UTC" {
		t.Fatalf("a dated finding keeps its place in time: %q", dated.Times.FirstObserved)
	}
	for _, b := range dated.Background {
		if b.Title == "Telnet allowed" && b.FirstSeen != "2026-07-12 18:10:00 UTC" {
			t.Errorf("a dated finding must carry its first-seen time: %+v", b)
		}
	}
}

// ---- D3: promotion triggers and refusals ------------------------------------------------

func promoBase() Report {
	return Report{
		States:         ReportStates{Analysis: "suspected", Impact: "unknown"},
		Times:          rcaReportTimes{DurationMS: (30 * time.Second).Milliseconds(), WindowEnd: "2026-11-11 00:08:00"},
		Eligibility:    rcaDocEligibility{CausalHeadline: true, PrimaryDevice: "edge-1", HeadlineID: "sig.ent.access.local-link-fault"},
		ConfirmingPair: rcaConfirmingPair{Basis: "none"},
	}
}

func TestPromotionRepeatOffenderTrigger(t *testing.T) {
	rep := promoBase()
	rep.SetRecurrence(2)
	if st := EvaluatePromotion(&rep, nil); st.Promoted {
		t.Fatalf("2 of 3 must not promote: %+v", st)
	}
	rep.SetRecurrence(RepeatOffenderMin)
	st := EvaluatePromotion(&rep, nil)
	if !st.Promoted || st.Basis != "auto" || st.Trigger != "repeat_offender" || !strings.Contains(st.Reason, "edge-1") {
		t.Fatalf("3 in 7 days must promote as a repeat offender: %+v", st)
	}
	rep.Validation = true
	if EvaluatePromotion(&rep, nil).Promoted {
		t.Fatal("a validation scenario never promotes")
	}
}

func TestPromotionMultiSiteControllerTrigger(t *testing.T) {
	rep := promoBase()
	rep.Eligibility.ControllerOrHub, rep.Eligibility.Sites = true, 1
	if EvaluatePromotion(&rep, nil).Promoted {
		t.Fatal("one site is not a multi-site outage")
	}
	rep.Eligibility.Sites = MultiSiteMin
	if st := EvaluatePromotion(&rep, nil); !st.Promoted || st.Trigger != "multi_site" {
		t.Fatalf("a controller reaching 2 sites must promote: %+v", st)
	}
	rep.Eligibility.ControllerOrHub = false
	if EvaluatePromotion(&rep, nil).Promoted {
		t.Fatal("2 sites without a controller/hub object is not this trigger")
	}
}

func TestPromotionRefusesNeverEstablishedAndNonMeasurementPair(t *testing.T) {
	outage := func() Report {
		r := promoBase()
		r.States = ReportStates{Analysis: "confirmed", Impact: "confirmed"}
		r.Times.DurationMS = (10 * time.Minute).Milliseconds()
		r.ConfirmingPair = rcaConfirmingPair{Observers: []string{"a", "b"}, Measured: true}
		return r
	}
	if st := func() PromotionStatus { r := outage(); return EvaluatePromotion(&r, nil) }(); !st.Promoted || st.Trigger != "real_outage" {
		t.Fatalf("fixture: a measured real outage promotes: %+v", st)
	}
	r := outage()
	r.ConfirmingPair = rcaConfirmingPair{Observers: []string{p424934Vmanage, "security:netrule"}, Measured: false, Basis: "includes a security rule"}
	if st := EvaluatePromotion(&r, nil); st.Promoted || !strings.Contains(st.Reason, "measurement sources") {
		t.Fatalf("a security/controller confirming pair must not promote: %+v", st)
	}
	r = outage()
	r.Eligibility.NeverEstablished = true
	r.SetRecurrence(10)
	if st := EvaluatePromotion(&r, nil); st.Promoted {
		t.Fatalf("a never-established peer never becomes an RCA document: %+v", st)
	}
}

// The pair is read from the slice: a security member is never a measurement.
func TestConfirmingPairFromSlice(t *testing.T) {
	hb := rcaHypBlob{}
	h := rcaHypEntry{ID: "x"}
	h.Verdict.IndependentPair = []string{"r1", "sec"}
	h.Verdict.TrustedModalities = []string{"control_plane", "security"}
	hb.Ranking.Hypotheses = []rcaHypEntry{h}
	sigs := []map[string]any{
		{"observer_id": "r1", "modality_class": "control_plane"},
		{"observer_id": "sec", "modality_class": "security"},
	}
	if p := buildConfirmingPair(hb, sigs); p.Measured || !p.Refutes() {
		t.Fatalf("security in the pair: %+v", p)
	}
	hb.Ranking.Hypotheses[0].Verdict.IndependentPair = []string{"r1", "flow1"}
	hb.Ranking.Hypotheses[0].Verdict.TrustedModalities = []string{"control_plane", "passive_flow"}
	sigs = append(sigs, map[string]any{"observer_id": "flow1", "modality_class": "passive_flow"})
	if p := buildConfirmingPair(hb, sigs); !p.Measured {
		t.Fatalf("two measurement planes: %+v", p)
	}
	hb.Ranking.Hypotheses[0].Verdict.IndependentPair = nil
	if p := buildConfirmingPair(hb, sigs); p.Measured || p.Refutes() {
		t.Fatalf("no recorded pair neither proves nor refutes: %+v", p)
	}
}

func TestRecurrenceQueryIsScopedAndEscaped(t *testing.T) {
	rep := promoBase()
	rep.Eligibility.PrimaryDevice = `edge-1' OR 1=1 --`
	q, ok := rep.RecurrenceQuery()
	if !ok {
		t.Fatal("expected a query")
	}
	for _, must := range []string{"FROM netops.corr_current FINAL", "AS repeat_count", `'edge-1\' OR 1=1 --'`,
		"'sig.ent.access.local-link-fault'", "INTERVAL 604800 SECOND", "toDateTime64('2026-11-11 00:08:00'"} {
		if !strings.Contains(q, must) {
			t.Errorf("query missing %q:\n%s", must, q)
		}
	}
	rep.Eligibility.HeadlineID = ""
	if _, ok := rep.RecurrenceQuery(); ok {
		t.Fatal("no causal headline → nothing to count")
	}
}

func TestControllerHubAndNeverEstablishedDetection(t *testing.T) {
	ctl := []map[string]any{{"kind": "device_unreachable", "modality_class": "management_plane", "entity_type": "device", "attrs": `{"device_role":"vSmart"}`}}
	if !rcaIsControllerOrHub(ctl) {
		t.Error("a vSmart is a controller")
	}
	if rcaIsControllerOrHub([]map[string]any{{"kind": "if_errors", "modality_class": "device_telemetry", "entity_type": "interface", "observer_type": "controller", "attrs": "{}"}}) {
		t.Error("the witness being a controller does not make the object one")
	}
	ne := []map[string]any{{"kind": "bgp_adjacency_change", "modality_class": "control_plane", "attrs": `{"transition_class":"never_established"}`}}
	if !rcaNeverEstablishedOnly(ne) {
		t.Error("trap transition_class never_established")
	}
	mixed := append(ne, map[string]any{"kind": "if_errors", "modality_class": "device_telemetry", "attrs": "{}"})
	if rcaNeverEstablishedOnly(mixed) {
		t.Error("a real fault beside the dead peer is not never-established-only")
	}
	up := []map[string]any{
		{"kind": "bgp_adjacency_change", "modality_class": "control_plane", "attrs": `{"bgp":{"transition_class":"never_established"}}`},
		{"kind": "bgp_adjacency_change", "modality_class": "control_plane", "attrs": `{"bgp":{"transition_class":"session_up"}}`},
	}
	if rcaNeverEstablishedOnly(up) {
		t.Error("a peer seen established is never never-established")
	}
}

// Coordinator fix (2026-11-11): IOS/IOS-XE clears the remote router-id on
// teardown, so 0.0.0.0 never decides. Only the transition class (trap
// bgp.transition_class, or the controller's correlation_hints.bgp_transition_class)
// or an explicit never_established flag marks a dead peer; "unknown" or an
// absent class is a possible real failure and must not block promotion.
func TestNeverEstablishedOnlyFromTransitionClass(t *testing.T) {
	ctl := func(attrs string) []map[string]any {
		return []map[string]any{{"kind": "bgp_adjacency_change", "modality_class": "control_plane",
			"collection_path": "via_controller", "source": "controller", "attrs": attrs}}
	}
	for name, attrs := range map[string]string{
		"router-id 0.0.0.0, no class":      `{"peer":"10.0.0.2","state":"idle","peer_router_id":"0.0.0.0"}`,
		"router-id unset hint, no class":   `{"peer":"10.0.0.2","state":"idle","correlation_hints":{"bgp_peer_routerid":"unset"}}`,
		"class unknown, router-id 0.0.0.0": `{"peer":"10.0.0.2","state":"idle","peer_router_id":"0.0.0.0","correlation_hints":{"bgp_transition_class":"unknown","bgp_peer_routerid":"unset"}}`,
		"class session_lost":               `{"peer":"10.0.0.2","correlation_hints":{"bgp_transition_class":"session_lost"}}`,
	} {
		if rcaNeverEstablishedOnly(ctl(attrs)) {
			t.Errorf("%s: must be treated as a possible real failure, not never-established", name)
		}
	}
	for name, attrs := range map[string]string{
		"controller class":  `{"peer":"10.0.0.2","correlation_hints":{"bgp_transition_class":"never_established","bgp_transition_basis":"x"}}`,
		"trap nested class": `{"peer":"10.0.0.2","bgp":{"transition_class":"never_established"}}`,
		"trap flat class":   `{"peer":"10.0.0.2","bgp.transition_class":"never_established"}`,
		"explicit flag":     `{"peer":"10.0.0.2","never_established":true}`,
	} {
		if !rcaNeverEstablishedOnly(ctl(attrs)) {
			t.Errorf("%s: must read as never-established", name)
		}
	}

	// end to end: a recurring BGP session-loss on one device (repeat-offender
	// trigger) whose controller reports carry a 0.0.0.0 router id and class
	// unknown still promotes; class never_established never does.
	build := func(attrs string) PromotionStatus {
		h := testHyp("sig.ent.wan-edge.bgp-peer-down", 0.9, "suspected", []string{"bgp_adjacency_change"}, nil, nil, "netops", false)
		meta := testMeta("open", "suspected", "sig.ent.wan-edge.bgp-peer-down", h)
		meta["affected"] = `{"devices":["edge-1"]}`
		rep := buildTestReport(t, meta, []map[string]any{
			testSig("bgp_adjacency_change", "control_plane", "vmanage-1", "device", "edge-1", "crit", "2026-07-12 18:12:00", true,
				map[string]any{"collection_path": "via_controller", "source": "controller", "attrs": attrs}),
			testSig("bgp_adjacency_change", "control_plane", "vmanage-1", "device", "edge-1", "crit", "2026-07-12 18:20:00", true,
				map[string]any{"collection_path": "via_controller", "source": "controller", "attrs": attrs}),
		})
		rep.SetRecurrence(5)
		return EvaluatePromotion(&rep, nil)
	}
	if st := build(`{"peer":"10.0.0.2","state":"idle","peer_router_id":"0.0.0.0","correlation_hints":{"bgp_transition_class":"unknown","bgp_peer_routerid":"unset"}}`); !st.Promoted {
		t.Fatalf("a recurring session loss with router-id 0.0.0.0 and class unknown must still promote: %+v", st)
	}
	if st := build(`{"peer":"10.0.0.2","state":"idle","correlation_hints":{"bgp_transition_class":"never_established"}}`); st.Promoted {
		t.Fatalf("a never-established peer must not promote: %+v", st)
	}
}

// ---- the PDF -----------------------------------------------------------------------------

func TestNocDocumentPDFRendersSectionsBandAndGuide(t *testing.T) {
	rep := p424934(t, true)
	html, err := RenderReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	last := -1
	for i, name := range RcaSectionNames {
		band := strings.ReplaceAll(name, "&", "&amp;")
		idx := strings.Index(doc, strconv.Itoa(i+1)+" · "+band)
		if idx < 0 || idx < last {
			t.Fatalf("section %d %q missing or out of order (%d < %d)", i+1, name, idx, last)
		}
		last = idx
	}
	guide := strings.Index(doc, "How to read this RCA")
	if guide < strings.Index(doc, "Appendix D · Integrity") {
		t.Fatal("the reading guide is the last page")
	}
	bgStart := strings.Index(doc, "7 · Background on this device (not a cause)")
	bgEnd := strings.Index(doc, "8 · Other explanations considered")
	band := doc[bgStart:bgEnd]
	for _, want := range []string{"Known security exposure on this device", "Telnet permitted on management lines", "never the cause"} {
		if !strings.Contains(band, want) {
			t.Errorf("background band missing %q", want)
		}
	}
	causeSec := doc[strings.Index(doc, "4 · Cause and how sure we are"):strings.Index(doc, "5 · How we know")]
	if !strings.Contains(causeSec, "Possibly because of") || strings.Contains(causeSec, "Confirmed cause") {
		t.Fatalf("section 4 must carry the honest phrase:\n%s", causeSec)
	}
	if !strings.Contains(doc, "vManage reported") {
		t.Error("section 5 must name the source in plain words")
	}
	// RCA_HTML_OUT (optional, owner review aid): write the rendered document so
	// it can be opened or printed in a browser.
	if out := os.Getenv("RCA_HTML_OUT"); out != "" {
		if err := os.WriteFile(out, html, 0o600); err != nil {
			t.Fatalf("write %s: %v", out, err)
		}
	}
	if strings.Contains(doc, "management_plane") || strings.Contains(doc, "Exposed device is also failing") {
		t.Error("raw token or raw template title in the document")
	}
}
