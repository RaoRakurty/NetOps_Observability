package main

// rca_evidence_summary_test.go — the NOC evidence read (owner directive
// 2026-07-18, docs/design/rca-evidence-summary.md): symptoms · independent
// sources · duration replace the raw count headline; per-symptom time-density
// series; verdict reason in operator words, never a percentage; raw
// observations demoted to a muted trailing fact; and the word "signal" gone
// from the rendered document.

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestEvidenceSummaryGroupsSymptomsWithDensity(t *testing.T) {
	meta := testMeta("open", "suspected", "sig.ent.wan-edge.bgp-peer-down",
		testHyp("sig.ent.wan-edge.bgp-peer-down", 0.5, "suspected",
			[]string{"bgp_adjacency_change"}, nil, nil, "isp", false))
	sigs := []map[string]any{
		// one symptom repeated 3x (persistence, not extra evidence) + one distinct
		testSig("probe_loss", "active_probe", "prober", "path", "p->x", "crit", "2026-07-12 18:10:30", true, nil),
		testSig("probe_loss", "active_probe", "prober", "path", "p->x", "crit", "2026-07-12 18:15:00", true,
			map[string]any{"signal_id": "s-probe_loss-2"}),
		testSig("probe_loss", "active_probe", "prober", "path", "p->x", "crit", "2026-07-12 18:29:00", true,
			map[string]any{"signal_id": "s-probe_loss-3"}),
		testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:12:00", true, nil),
	}
	rep := buildTestReport(t, meta, sigs)
	es := rep.Evidence
	if es.SymptomCount != 2 || len(es.Symptoms) != 2 {
		t.Fatalf("want 2 distinct symptoms (repeats collapse), got %d: %+v", es.SymptomCount, es.Symptoms)
	}
	// onset order: probe_loss (18:10:30) before bgp (18:12)
	if es.Symptoms[0].Kind != "probe_loss" || es.Symptoms[1].Kind != "bgp_adjacency_change" {
		t.Fatalf("symptoms must sort by onset: %+v", es.Symptoms)
	}
	first := es.Symptoms[0]
	if first.Observations != 3 {
		t.Fatalf("repeat count = %d, want 3", first.Observations)
	}
	if len(first.Buckets) != rcaSymptomBuckets {
		t.Fatalf("buckets len = %d", len(first.Buckets))
	}
	sum := 0
	nonEmpty := 0
	for _, b := range first.Buckets {
		sum += b
		if b > 0 {
			nonEmpty++
		}
	}
	if sum != 3 || nonEmpty < 2 {
		t.Fatalf("density must place all 3 observations across the window: sum=%d spread=%d", sum, nonEmpty)
	}
	if es.Observations == 0 {
		t.Fatal("raw observation total must still be disclosed (muted), never hidden")
	}
	if es.VerdictReason == "" || strings.Contains(es.VerdictReason, "%") {
		t.Fatalf("verdict reason must be words, never a percentage: %q", es.VerdictReason)
	}
}

func TestEvidenceSummarySoloSourceReadsHonestlyWeak(t *testing.T) {
	meta := testMeta("open", "suspected", "undetermined", nil)
	rep := buildTestReport(t, meta, []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "p->x", "high", "2026-07-12 18:12:00", true, nil),
	})
	r := rep.Evidence.VerdictReason
	if !strings.Contains(r, "only active checks saw this") || !strings.Contains(r, "second independent source") {
		t.Fatalf("single-source case must name the solo source and the gap: %q", r)
	}
}

func TestBucketObservationTimesIsPureAndClamped(t *testing.T) {
	start := time.Date(2026, 7, 12, 18, 0, 0, 0, time.UTC)
	end := start.Add(20 * time.Minute)
	got := bucketObservationTimes([]time.Time{
		start,                        // first bucket
		start.Add(10 * time.Minute),  // middle
		end,                          // clamps into the last bucket
		start.Add(-1 * time.Minute),  // clamps into the first
		end.Add(5 * time.Minute),     // clamps into the last
	}, start, end, 4)
	want := []int{2, 0, 1, 2}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("buckets = %v, want %v", got, want)
		}
	}
}

func TestRenderedReportCarriesNoSignalWording(t *testing.T) {
	meta := testMeta("closed", "suspected", "sig.ent.wan-edge.bgp-peer-down",
		testHyp("sig.ent.wan-edge.bgp-peer-down", 0.5, "suspected",
			[]string{"bgp_adjacency_change"}, []string{"probe_loss"}, nil, "isp", false))
	sigs := []map[string]any{
		testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss_clear", "active_probe", "prober", "path", "p->x", "info", "2026-07-12 18:20:00", false,
			map[string]any{"clear_ts": "2026-07-12 18:20:00"}),
	}
	rep := buildTestReport(t, meta, sigs)
	html, err := renderRcaReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	// The word that caused the misread must not reach the document (the design's
	// terminology rule); internal/API names are unaffected. Report EVERY
	// occurrence so a wording regression is fixed in one pass, not one-by-one.
	for _, idx := range regexp.MustCompile(`(?i)\bsignals?\b`).FindAllStringIndex(string(html), -1) {
		lo := idx[0] - 60
		if lo < 0 {
			lo = 0
		}
		hi := idx[1] + 40
		if hi > len(html) {
			hi = len(html)
		}
		t.Errorf("rendered report still says %q: …%s…", string(html)[idx[0]:idx[1]], string(html)[lo:hi])
	}
	if !strings.Contains(string(html), "Evidence summary") {
		t.Fatal("the evidence summary section must render")
	}
	if !strings.Contains(string(html), "raw observations collected") {
		t.Fatal("the raw total must render as the muted trailing fact")
	}
}
