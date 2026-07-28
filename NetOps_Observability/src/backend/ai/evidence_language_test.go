package ai

import (
	"strings"
	"testing"
)

// v1Blob builds a corr_objects.hypotheses blob in the engine's frozen shape
// (scoring.py RankingResult.to_dict → {"ranking":{"hypotheses":[...]}}), the
// same contract topHypothesisVoice and the correlations UI read.
const v1CorroboratedBlob = `{
  "ranking": {
    "top_hypothesis": "sig.ent.wan-edge.sdwan-tunnel-controller-corroborated",
    "verdict_tier": "confirmed",
    "hypotheses": [
      {
        "id": "sig.ent.wan-edge.sdwan-tunnel-controller-corroborated",
        "title": "SD-WAN tunnel degraded — controller corroborated",
        "coverage": 1.0,
        "confidence": 0.91,
        "confidence_label": "confirmed",
        "contradicted": false,
        "satisfied": ["controller_bfd_down", "bfd_session_down", "tunnel_loss"],
        "missing": [],
        "contradictions": [],
        "operator_phrase": "Tunnel to branch degraded; controller and probes agree.",
        "verdict": {
          "owner": "wan",
          "verdict_tier": "confirmed",
          "reasons": ["independent pair found"],
          "modality_coverage": ["active_probe", "control_plane", "management_plane"],
          "observer_coverage": ["prober-1", "vmanage", "dmz-fw"],
          "independent_pair": ["prober-1", "vmanage"]
        }
      },
      {
        "id": "sig.ent.lan.link-flap",
        "title": "",
        "confidence": 0.4,
        "confidence_label": "suspected",
        "satisfied": ["link_flap"],
        "verdict": {"verdict_tier": "suspected", "modality_coverage": ["control_plane"]}
      }
    ]
  },
  "grounding_context": {"topology_version": "t1", "seams": []}
}`

const v1ControllerOnlyBlob = `{
  "ranking": {
    "hypotheses": [
      {
        "id": "sig.ent.campus.controller-device-unreachable",
        "title": "Device unreachable — controller report",
        "confidence": 0.55,
        "confidence_label": "suspected",
        "contradicted": false,
        "satisfied": ["controller_device_unreachable"],
        "verdict": {
          "verdict_tier": "suspected",
          "modality_coverage": ["management_plane"],
          "observer_coverage": ["meraki"],
          "independent_pair": null
        }
      }
    ]
  }
}`

const v1ContradictedBlob = `{
  "ranking": {
    "hypotheses": [
      {
        "id": "sig.ent.wan-edge.sdwan-tunnel-degraded",
        "title": "SD-WAN tunnel degraded",
        "confidence": 0.6,
        "confidence_label": "suspected",
        "contradicted": true,
        "satisfied": ["tunnel_loss"],
        "contradictions": ["controller_tunnel_state"],
        "verdict": {
          "verdict_tier": "suspected",
          "modality_coverage": ["active_probe"],
          "observer_coverage": ["prober-1"]
        }
      }
    ]
  }
}`

func findEvidenceText(t *testing.T, texts []string, want string) string {
	t.Helper()
	for _, x := range texts {
		if strings.Contains(x, want) {
			return x
		}
	}
	t.Fatalf("no evidence item contains %q; items:\n%s", want, strings.Join(texts, "\n"))
	return ""
}

func renderTexts(blob string) []string {
	items := RankedHypothesisItems("11111111-2222-3333-4444-555555555555", "#/x", ParseRankedHypotheses(blob))
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Text)
	}
	return out
}

func TestRankedHypothesisItemsCorroborated(t *testing.T) {
	texts := renderTexts(v1CorroboratedBlob)

	// Candidate causes render with the confidence LABEL (voice contract), not a raw score.
	top := findEvidenceText(t, texts, "candidate cause: SD-WAN tunnel degraded — controller corroborated")
	if !strings.Contains(top, "confirmed") {
		t.Errorf("top candidate should carry its confidence label: %q", top)
	}
	// The empty-title runner-up falls back to the humanized signature id.
	findEvidenceText(t, texts, "candidate cause: Link flapping — LAN")

	// Evidence basis: humanized modalities + the independent pair.
	basis := findEvidenceText(t, texts, "evidence basis:")
	for _, want := range []string{"active probes", "control-plane events", "controller (management plane)", "independently confirmed by prober-1 and vmanage"} {
		if !strings.Contains(basis, want) {
			t.Errorf("evidence basis missing %q: %q", want, basis)
		}
	}

	// Controller clause: reported + corroborated wording (never the capped wording).
	ctrl := findEvidenceText(t, texts, "controller reported: BFD session down")
	if !strings.Contains(ctrl, "corroborated by direct telemetry") {
		t.Errorf("corroborated case must say so: %q", ctrl)
	}
	if strings.Contains(ctrl, "controller-only") {
		t.Errorf("corroborated case must not carry the controller-only cap: %q", ctrl)
	}
}

func TestRankedHypothesisItemsControllerOnly(t *testing.T) {
	texts := renderTexts(v1ControllerOnlyBlob)

	ctrl := findEvidenceText(t, texts, "controller reported: device unreachable")
	if !strings.Contains(ctrl, "controller-only evidence") || !strings.Contains(ctrl, "suspected") {
		t.Errorf("controller-only case must disclose the independence cap: %q", ctrl)
	}
	basis := findEvidenceText(t, texts, "evidence basis: controller (management plane)")
	if !strings.Contains(basis, "single evidence stream cannot confirm") {
		t.Errorf("single-modality basis must disclose it cannot confirm alone: %q", basis)
	}
}

func TestRankedHypothesisItemsContradiction(t *testing.T) {
	texts := renderTexts(v1ContradictedBlob)
	contra := findEvidenceText(t, texts, "contradicting evidence present:")
	if !strings.Contains(contra, "controller view: tunnel state change") {
		t.Errorf("controller contradiction should be labelled as the controller's view: %q", contra)
	}
}

// The live catalog writes clause ALTERNATIONS into satisfied (the expression,
// not the matched alternative) — seen live on the mock-nms validation object.
const v1AlternationBlob = `{
  "ranking": {
    "hypotheses": [
      {
        "id": "sig.ent.wan-edge.sdwan-tunnel-fault-controller",
        "title": "SD-WAN tunnel fault (controller-witnessed)",
        "confidence_label": "suspected",
        "satisfied": ["controller_tunnel_state|controller_bfd_down", "controller_alarm|bfd_session_down"],
        "verdict": {
          "verdict_tier": "suspected",
          "modality_coverage": ["management_plane"],
          "observer_coverage": ["vmanage"]
        }
      }
    ]
  }
}`

func TestRankedHypothesisItemsClauseAlternation(t *testing.T) {
	texts := renderTexts(v1AlternationBlob)
	ctrl := findEvidenceText(t, texts, "controller reported:")
	if !strings.Contains(ctrl, "tunnel state change / BFD session down") {
		t.Errorf("pipe alternation should render as 'A / B': %q", ctrl)
	}
	if strings.Contains(ctrl, "|") || strings.Contains(ctrl, "controller_") {
		t.Errorf("raw clause tokens leaked into NOC text: %q", ctrl)
	}
	// The mixed alternation (controller_alarm|bfd_session_down) proves neither
	// witness, and coverage is management_plane-only → the cap must be disclosed.
	if !strings.Contains(ctrl, "controller-only evidence") {
		t.Errorf("management_plane-only coverage must carry the cap: %q", ctrl)
	}
}

func TestSplitControllerKindsAlternations(t *testing.T) {
	ctrl, direct := splitControllerKinds([]string{
		"controller_bfd_down",                        // pure controller
		"controller_tunnel_state|controller_alarm",   // pure controller alternation
		"bfd_session_down",                           // pure direct
		"controller_device_unreachable|icmp_timeout", // mixed → neither
	})
	if len(ctrl) != 2 || len(direct) != 1 {
		t.Errorf("splitControllerKinds = ctrl %v direct %v; want 2 ctrl, 1 direct (mixed dropped)", ctrl, direct)
	}
}

func TestParseRankedHypothesesShapes(t *testing.T) {
	// Legacy pre-v1 blob (bare array) → nil, so the caller takes the legacy path.
	if got := ParseRankedHypotheses(`[{"signature":"sig.x","score":0.5}]`); got != nil {
		t.Errorf("bare-array blob must parse as nil (legacy path), got %d hypotheses", len(got))
	}
	if got := ParseRankedHypotheses(""); got != nil {
		t.Errorf("empty blob must parse as nil")
	}
	if got := ParseRankedHypotheses("{not json"); got != nil {
		t.Errorf("garbage must parse as nil, never panic")
	}
	// Already-parsed map (ClickHouse FORMAT JSON can hand back objects).
	m := map[string]any{"ranking": map[string]any{"hypotheses": []any{
		map[string]any{"id": "sig.y", "confidence_label": "likely"},
	}}}
	got := ParseRankedHypotheses(m)
	if len(got) != 1 || got[0].ID != "sig.y" || got[0].ConfidenceLabel != "likely" {
		t.Errorf("map-shaped blob should parse: %+v", got)
	}
}

func TestTopHypothesisVoiceFromBlob(t *testing.T) {
	phrase, label := TopHypothesisVoice(v1CorroboratedBlob)
	if phrase != "Tunnel to branch degraded; controller and probes agree." || label != "confirmed" {
		t.Errorf("topHypothesisVoice = (%q, %q)", phrase, label)
	}
	if p, l := TopHypothesisVoice(`[]`); p != "" || l != "" {
		t.Errorf("legacy blob voice should be empty, got (%q, %q)", p, l)
	}
}
