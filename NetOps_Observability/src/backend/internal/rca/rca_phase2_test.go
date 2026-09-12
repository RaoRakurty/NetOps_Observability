// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_phase2_test.go — Phase 2 of the postmortem spec (report layout, causal
// chain, glossary, quantified-impact + detection-milestone rendering).
//
// The rendered documents for both named regression fixtures snapshot under
// testdata/ (rca_phase2_*.html.snapshot) so the owner reviews the exact
// document shape before deploy (spec gate). Regenerate deliberately with
// RCA_UPDATE_SNAPSHOTS=1.

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fixtureSnapshotBytes — the raw-bytes sibling of fixtureSnapshot: compares
// rendered document bytes against the stored snapshot; a missing snapshot (or
// RCA_UPDATE_SNAPSHOTS=1) writes it for owner review.
func fixtureSnapshotBytes(t *testing.T, name string, got []byte) {
	t.Helper()
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
		t.Fatalf("rendered document drifted from the owner-reviewed snapshot %s.\nIf the change is intentional, regenerate with RCA_UPDATE_SNAPSHOTS=1 and have the owner re-review.", path)
	}
}

var rcaPhase2SectionBands = []string{
	"1 · Executive summary",
	"2 · Impact",
	"3 · What happened",
	"4 · Trigger",
	"5 · Root cause and contributing factors",
	"6 · Detection and response",
	"7 · Mitigation and service recovery",
	"8 · Corrective actions",
	"9 · Lessons learned",
	"10 · Detailed timeline",
	"11 · Evidence appendix",
	"12 · Glossary",
}

// ---- A. report layout: the 12-section order -----------------------------------

func TestPhase2TwelveSectionOrder(t *testing.T) {
	rep := buildRichFixtureReport(t)
	html, err := RenderReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	last := -1
	for _, band := range rcaPhase2SectionBands {
		idx := strings.Index(doc, band)
		if idx < 0 {
			t.Fatalf("document missing postmortem section %q", band)
		}
		if idx < last {
			t.Fatalf("section %q out of order (index %d < previous %d)", band, idx, last)
		}
		last = idx
	}
	// Masthead stays on page 1, above every numbered section.
	if m := strings.Index(doc, `class="brand"`); m < 0 || m > strings.Index(doc, rcaPhase2SectionBands[0]) {
		t.Fatal("masthead must precede section 1")
	}
}

// Sections with absent data render honest absence — never silently omitted,
// never fabricated.
func TestPhase2HonestAbsenceInEverySection(t *testing.T) {
	rep := buildFixtureP3335CF(t)
	html, err := RenderReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	for _, band := range rcaPhase2SectionBands {
		if !strings.Contains(doc, band) {
			t.Errorf("section %q must render even with absent data", band)
		}
	}
	for _, want := range []string{
		// Trigger: not determined, stated.
		"Not determined. The engine does not distinguish the incident trigger",
		// Contributing factors: not determined, stated.
		"The engine does not yet separate contributing factors",
		// Lessons learned: closed on an operational assessment, stated.
		"Lessons learned belong to the promoted postmortem workflow",
		// Milestones that are absent are named as absent.
		"a milestone without a sourced timestamp is stated as absent, never estimated",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("honest-absence wording missing: %q", want)
		}
	}
}

// Artifact-class watermarking is preserved through the Phase 2 layout:
// P-D96E4C stays a watermarked validation assessment, P-3335CF stays an
// operational assessment — neither resembles a production postmortem.
func TestPhase2ArtifactClassPreserved(t *testing.T) {
	val := buildFixturePD96E4C(t)
	html, err := RenderReportHTML(val)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	if !strings.Contains(doc, "VALIDATION SCENARIO — NOT A PRODUCTION INCIDENT") {
		t.Fatal("validation watermark lost in the Phase 2 layout")
	}
	if !strings.Contains(doc, "Validation incident assessment") {
		t.Fatal("artifact-class line lost")
	}
	if !strings.Contains(doc, "no production corrective-action commitments") {
		t.Fatal("validation document must disclaim corrective-action commitments")
	}

	op := buildFixtureP3335CF(t)
	html2, err := RenderReportHTML(op)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(string(html2), "Operational incident assessment") {
		t.Fatal("P-3335CF must render as an operational assessment")
	}
}

// ---- B. causal chain rendering -------------------------------------------------

func TestPhase2CausalChainStepsAndBranches(t *testing.T) {
	rep := buildRichFixtureReport(t)
	cc := rep.CausalChain
	if !cc.Available || len(cc.Steps) != 4 {
		t.Fatalf("causal chain = %+v, want 4 steps", cc)
	}
	// numbered primary sequence
	for i, s := range cc.Steps {
		if s.Number != i+1 {
			t.Fatalf("step %d numbered %d", i, s.Number)
		}
	}
	// root step carries the hypothesized-origin role, never a causal fact claim
	if !strings.Contains(cc.Steps[0].CausalRole, "likely origin") ||
		!strings.Contains(cc.Steps[0].CausalRole, "not established") {
		t.Fatalf("root step role = %q", cc.Steps[0].CausalRole)
	}
	// steps after the first link with TEMPORAL language only
	for _, s := range cc.Steps[1:] {
		if s.Link != "followed by" {
			t.Fatalf("step %d link = %q, want temporal 'followed by'", s.Number, s.Link)
		}
	}
	// the unwitnessed rung is epistemically unknown and says "not observed"
	if cc.Steps[1].EpistemicState != epistemicUnknown ||
		!strings.Contains(cc.Steps[1].EpistemicBasis, "not observed") {
		t.Fatalf("unwitnessed step = %+v", cc.Steps[1])
	}
	// the multi-vantage probe-loss rung is corroborated with evidence + interval
	loss := cc.Steps[2]
	if loss.EpistemicState != epistemicCorroborated {
		t.Fatalf("multi-source step epistemic = %q, want corroborated", loss.EpistemicState)
	}
	if len(loss.Evidence) == 0 || len(loss.EvidenceIDs) == 0 || loss.Interval == "" {
		t.Fatalf("corroborated step must carry evidence refs + interval: %+v", loss)
	}
	// branches: the two non-leading hypotheses, the contradicted one marked so
	if len(cc.Branches) != 2 {
		t.Fatalf("branches = %+v, want 2", cc.Branches)
	}
	foundContradicted := false
	for _, b := range cc.Branches {
		if b.EpistemicState == epistemicContradicted {
			foundContradicted = true
			if len(b.Contradictions) == 0 {
				t.Fatalf("contradicted branch must carry its contradicting evidence: %+v", b)
			}
		}
	}
	if !foundContradicted {
		t.Fatal("the contradicted alternative must render as contradicted")
	}

	html, err := RenderReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	for _, want := range []string{
		"How the failure propagated", "likely origin", "not observed",
		"followed by the previous step", "Alternative hypotheses — branches",
		"sequence is not causation",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("causal-chain rendering missing %q", want)
		}
	}
	// No fabricated confidence percentages: the hypothesis floats (0.62/0.31)
	// never render, as a number or a percent.
	for _, banned := range []string{"0.62", "62%", "0.31", "31%", "0.9)"} {
		if strings.Contains(doc, banned) {
			t.Errorf("document renders a fabricated confidence number %q", banned)
		}
	}
}

func TestPhase2CausalChainHonestWhenAbsent(t *testing.T) {
	meta := testMeta("open", "undetermined", "undetermined", nil)
	rep := buildTestReport(t, meta, []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "prober->svc", "high", "2026-07-12 18:12:00", true, nil),
	})
	if rep.CausalChain.Available {
		t.Fatalf("no ranking blob must mean no causal sequence: %+v", rep.CausalChain)
	}
	if !strings.Contains(rep.CausalChain.Note, "none is invented") {
		t.Fatalf("absent chain must state honest absence: %q", rep.CausalChain.Note)
	}
	html, err := RenderReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(string(html), "none is invented") {
		t.Fatal("rendered document must state the absent causal sequence")
	}
}

// ---- C. glossary ---------------------------------------------------------------

func TestPhase2GlossaryIsDynamic(t *testing.T) {
	// P-3335CF: active production case, no validation, no recovery.
	op := buildFixtureP3335CF(t)
	terms := map[string]bool{}
	for _, g := range op.Glossary {
		terms[g.Term] = true
		if g.Definition == "" {
			t.Fatalf("term %q has no definition", g.Term)
		}
	}
	// semantics terms present in this report are defined
	for _, want := range []string{"observed", "suspected", "independent evidence", "not measured", "synthetic check"} {
		if !terms[want] {
			t.Errorf("glossary missing used term %q (has %v)", want, op.Glossary)
		}
	}
	// terms NOT used by this report do not appear
	for _, absent := range []string{"validation scenario", "recovery validation", "contradicted"} {
		if terms[absent] {
			t.Errorf("glossary includes unused term %q — it must be dynamic", absent)
		}
	}

	// P-D96E4C: validation scenario, confirmed verdict → those terms appear.
	val := buildFixturePD96E4C(t)
	vterms := map[string]bool{}
	for _, g := range val.Glossary {
		vterms[g.Term] = true
	}
	for _, want := range []string{"validation scenario", "confirmed", "observed"} {
		if !vterms[want] {
			t.Errorf("validation glossary missing used term %q", want)
		}
	}
}

func TestPhase2GlossaryDefinesInferredWhenRecoveryInferred(t *testing.T) {
	// A closed window with no recovery evidence → recovery "inferred" — the
	// glossary must define "inferred" (spec §5: always define when present).
	meta := testMeta("closed", "suspected", "undetermined",
		testHyp("sig.ent.wan-edge.bgp-peer-down", 0.5, "suspected",
			[]string{"bgp_adjacency_change"}, nil, nil, "isp", false))
	rep := buildTestReport(t, meta, []map[string]any{
		testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:12:00", true, nil),
	})
	if rep.States.Recovery != "inferred" {
		t.Fatalf("precondition: recovery = %q, want inferred", rep.States.Recovery)
	}
	found := false
	for _, g := range rep.Glossary {
		if g.Term == "inferred" {
			found = true
		}
	}
	if !found {
		t.Fatal("glossary must define 'inferred' when the report uses it")
	}
}

// ---- D. quantified-impact rendering --------------------------------------------

func TestPhase2ImpactRenderingHonest(t *testing.T) {
	rep := buildFixtureP3335CF(t)
	html, err := RenderReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	for _, want := range []string{
		"Quantified impact — every value with provenance",
		"Active users affected", "Synthetic failure rate",
		"never converted into affected-user counts",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("impact section missing %q", want)
		}
	}
	// the synthetic rate is measured (100%); real-user counts render as
	// "Not measured" — never zero, never converted.
	if !strings.Contains(doc, "100%") {
		t.Error("measured synthetic failure rate must render its value")
	}
	if n := strings.Count(doc, "Not measured"); n < 6 {
		t.Errorf("expected ≥6 'Not measured' rows (real-user + unsourced measures), got %d", n)
	}
	for _, banned := range []string{"0 users", "0 sessions", "0 transactions"} {
		if strings.Contains(doc, banned) {
			t.Errorf("unmeasured impact rendered as zero: %q", banned)
		}
	}
}

// ---- E. detection milestones ---------------------------------------------------

func TestPhase2DetectionMilestonesRendering(t *testing.T) {
	rep := buildFixtureP3335CF(t)
	html, err := RenderReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	if !strings.Contains(doc, "Detection milestones") || !strings.Contains(doc, "First credible failure") {
		t.Fatal("sourced milestone must render with its label")
	}
	if !strings.Contains(doc, "Source of this timestamp") {
		t.Fatal("milestone table must name each timestamp's source")
	}
	// absent milestones are listed as absent, never estimated
	if !strings.Contains(doc, "Not recorded:") || !strings.Contains(doc, "First acknowledgement") {
		t.Fatal("absent milestones must be named as not recorded")
	}
	// no comparative statement exists without both sourced endpoints
	if len(rep.Semantics.Comparisons) != 0 {
		t.Fatalf("fixture has one sourced milestone; comparisons = %+v", rep.Semantics.Comparisons)
	}
	if strings.Contains(doc, "Comparative durations") {
		t.Fatal("comparative durations must not render without both endpoints")
	}
}

func TestPhase2ComparativeDurationsRenderWhenSourced(t *testing.T) {
	// A case whose trigger observation is in the slice gains a sourced
	// "first Correlix detection" → detection lag becomes computable.
	meta := testMeta("open", "suspected", "sig.ent.app.customer-path-degraded",
		testHyp("sig.ent.app.customer-path-degraded", 0.55, "suspected",
			[]string{"synthetic_http_failure"}, nil, nil, "app_team", false))
	trig := testSig("synthetic_http_failure", "active_probe", "prober-fra", "app", "crm-portal", "high", "2026-07-12 18:14:00", true,
		map[string]any{"probe_scope": "customer_path"})
	meta["trigger_signal"] = trig["signal_id"]
	sigs := []map[string]any{
		testSig("synthetic_http_failure", "active_probe", "prober-fra", "app", "crm-portal", "high", "2026-07-12 18:12:00", true,
			map[string]any{"probe_scope": "customer_path"}),
		trig,
	}
	rep := buildTestReport(t, meta, sigs)
	if len(rep.Semantics.Comparisons) == 0 {
		t.Fatalf("expected a detection-lag comparison, milestones = %+v", rep.Semantics.Milestones)
	}
	html, err := RenderReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	if !strings.Contains(doc, "Comparative durations") || !strings.Contains(doc, "Detection lag") {
		t.Fatal("sourced comparison must render")
	}
	if !strings.Contains(doc, "source lineage are both present") {
		t.Fatal("comparison rendering must state its lineage rule")
	}
}

// ---- detailed timeline ---------------------------------------------------------

func TestPhase2DetailedTimelineSourcedOnly(t *testing.T) {
	rep := buildRichFixtureReport(t)
	if len(rep.Timeline) == 0 {
		t.Fatal("rich fixture must produce timeline entries")
	}
	for _, e := range rep.Timeline {
		if e.TS == "" || e.Event == "" || e.Source == "" {
			t.Fatalf("timeline entry without ts/event/source: %+v", e)
		}
	}
	// chronological
	for i := 1; i < len(rep.Timeline); i++ {
		if rep.Timeline[i].TS < rep.Timeline[i-1].TS {
			t.Fatalf("timeline not chronological at %d: %q < %q", i, rep.Timeline[i].TS, rep.Timeline[i-1].TS)
		}
	}
}

// ---- style constraints (owner-enforced) ----------------------------------------

func TestPhase2NoEngineJargonInDocument(t *testing.T) {
	for name, rep := range map[string]Report{
		"rich":    buildRichFixtureReport(t),
		"p3335cf": buildFixtureP3335CF(t),
		"pd96e4c": buildFixturePD96E4C(t),
	} {
		html, err := RenderReportHTML(rep)
		if err != nil {
			t.Fatalf("%s render: %v", name, err)
		}
		doc := string(html)
		// no signature IDs, no engine vocabulary, no grey observed/not-observed
		// boxes, no "Signals: N" counts.
		for _, banned := range []string{"sig.ent.", "modality class", "modality_class", "Signals:"} {
			if strings.Contains(doc, banned) {
				t.Errorf("%s: rendered document contains engine jargon %q", name, banned)
			}
		}
		for _, m := range regexp.MustCompile(`(?i)\bsignals?\b`).FindAllString(doc, -1) {
			t.Errorf("%s: rendered document contains the word %q", name, m)
		}
	}
}

// ---- owner-review snapshots (spec gate: no deploy until reviewed) --------------

func TestPhase2FixtureDocumentSnapshots(t *testing.T) {
	op := buildFixtureP3335CF(t)
	opHTML, err := RenderReportHTML(op)
	if err != nil {
		t.Fatalf("render p3335cf: %v", err)
	}
	fixtureSnapshotBytes(t, "rca_phase2_p3335cf.html.snapshot", opHTML)

	val := buildFixturePD96E4C(t)
	valHTML, err := RenderReportHTML(val)
	if err != nil {
		t.Fatalf("render pd96e4c: %v", err)
	}
	fixtureSnapshotBytes(t, "rca_phase2_pd96e4c.html.snapshot", valHTML)
}
