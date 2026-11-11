// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// headline_background_test.go — Iris and the background stories (owner D1/D4,
// 2026-11-11). A standing security posture/exposure finding is narrated as
// background on the device: never the cause, never "confirmed", never with a
// cause role; Iris speaks one of the four fixed phrases, never a percentage.

import (
	"strings"
	"testing"
)

// The P-424934 blob: the exposure story on top (confirmed by a security +
// controller pair), the BGP story (suspected) behind it.
const p424934Blob = `{"ranking":{"hypotheses":[
 {"id":"sig.ent.security.exposure-story","confidence":1,"confidence_label":"confirmed",
  "operator_phrase":"This device carries a known exposure and is showing a network fault at the same time",
  "verdict":{"verdict_tier":"confirmed","independent_pair":["ctl-vmanage-1","security:netrule"]}},
 {"id":"sig.ent.wan-edge.bgp-peer-flap","confidence":1,"confidence_label":"suspected",
  "operator_phrase":"A WAN routing session is flapping",
  "verdict":{"verdict_tier":"suspected"}}]}}`

func TestHeadlineSkipsTheBackgroundStory(t *testing.T) {
	h := HeadlineOf(p424934Blob, "confirmed")
	if !h.Demoted || h.Tier != "suspected" || h.ID != "sig.ent.wan-edge.bgp-peer-flap" {
		t.Fatalf("headline = %+v", h)
	}
	if h.Phrase != "A WAN routing session is flapping" || h.Label != "suspected" {
		t.Fatalf("the voice must be the causal story's: %+v", h)
	}
	if len(h.Background) != 1 || !strings.HasPrefix(h.Background[0], "background on this device (not a cause): Known security exposure on this device") {
		t.Fatalf("background = %v", h.Background)
	}
	// legacy callers get the causal voice too
	if p, l := TopHypothesisVoice(p424934Blob); p != h.Phrase || l != "suspected" {
		t.Fatalf("TopHypothesisVoice = %q/%q", p, l)
	}
	// background-only → nothing to be sure about
	only := HeadlineOf(`{"ranking":{"hypotheses":[{"id":"sig.ent.security.hardening-drift-story","confidence_label":"confirmed","verdict":{"verdict_tier":"confirmed"}}]}}`, "confirmed")
	if !only.Demoted || only.Tier != "undetermined" || only.Phrase != "" || len(only.Background) != 1 {
		t.Fatalf("background-only headline = %+v", only)
	}
	// the engine flag is honoured for any id
	flagged := HeadlineOf(`{"ranking":{"hypotheses":[{"id":"sig.x.story","context_story":true},{"id":"sig.ent.access.local-link-fault","verdict":{"verdict_tier":"suspected"}}]}}`, "confirmed")
	if !flagged.Demoted || flagged.ID != "sig.ent.access.local-link-fault" {
		t.Fatalf("flagged headline = %+v", flagged)
	}
}

func TestRankedItemsNarrateBackgroundWithoutACauseRole(t *testing.T) {
	items := RankedHypothesisItems("11111111-2222-3333-4444-555555555555", "#/x", ParseRankedHypotheses(p424934Blob))
	var engine, background []EvidenceItem
	for _, it := range items {
		switch {
		case it.CauseRole == CauseRoleEngine && strings.HasPrefix(it.Text, "candidate cause"):
			engine = append(engine, it)
		case strings.HasPrefix(it.Text, "background on this device (not a cause)"):
			background = append(background, it)
		}
	}
	if len(engine) != 1 || !strings.Contains(engine[0].Text, "BGP peer flapping") {
		t.Fatalf("the engine's leading cause must be the BGP story: %+v", engine)
	}
	if len(background) != 1 || background[0].CauseRole != "" || background[0].Verdict != "" {
		t.Fatalf("background must carry no cause role and no verdict: %+v", background)
	}
	for _, it := range items {
		if it.CauseRole != "" && strings.Contains(strings.ToLower(it.Text), "exposure") {
			t.Fatalf("the exposure story was narrated as a cause: %+v", it)
		}
	}
}

func TestRCAVerdictNarratesBackgroundNeverConfirmed(t *testing.T) {
	ds := newMockDS()
	ds.problems["t-a"]["pbg"] = &Problem{
		ID: "pbg", Title: "Routing adjacency change", Verdict: "suspected", ConfidenceLabel: "suspected",
		OperatorPhrase: "A WAN routing session is flapping", SignalCount: 3, NodeCount: 1,
		Background: []string{"background on this device (not a cause): Known security exposure on this device"},
	}
	reg := Tools(ds)
	reg.AddTroubleshootTools(ds, tsDeps())
	res := mustRun(t, reg, "get_rca_verdict", ToolArgs{"correlation_id": "pbg"})
	joined := ""
	sawBackground := false
	for _, it := range res.Items {
		joined += it.Text + " | "
		if strings.HasPrefix(it.Text, "background on this device (not a cause)") {
			sawBackground = true
			if it.CauseRole != "" || it.Verdict != "" {
				t.Fatalf("background must carry no cause role or verdict: %+v", it)
			}
		}
	}
	if !sawBackground {
		t.Fatalf("background was not narrated: %q", joined)
	}
	if !strings.Contains(joined, "Possibly because of routing adjacency change") {
		t.Fatalf("the header must speak the suspected phrase: %q", joined)
	}
	if strings.Contains(joined, "Confirmed cause") || strings.Contains(joined, "engine confidence") || strings.Contains(joined, "%") {
		t.Fatalf("a background-backed case is never confirmed and never a percentage: %q", joined)
	}
}
