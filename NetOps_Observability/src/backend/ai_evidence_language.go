package main

import (
	"encoding/json"
	"fmt"
	"netops/backend/internal/noclabel"
	"strings"

	"netops/backend/ai"
)

// ai_evidence_language.go — renders the corr object's hypotheses blob (the
// engine's frozen ranking contract: {"ranking":{"hypotheses":[...]}} from
// scoring.py RankingResult.to_dict) into cited AI evidence items. This is the
// NMS P6 "AI evidence answers" seam: the assistant answers "what did the
// controller report / is this confirmed by telemetry or controller-only /
// which sources agree" straight from what the engine already persisted — no
// new retrieval, no re-derivation (the engine reasons, the AI narrates).

// rankedHypothesis mirrors the fields of HypothesisScore.to_dict the AI
// narrates. Unknown fields are ignored; absent ones stay zero — the renderer
// degrades to fewer items, never wrong ones.
type rankedHypothesis struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Confidence      float64  `json:"confidence"`
	ConfidenceLabel string   `json:"confidence_label"`
	Contradicted    bool     `json:"contradicted"`
	Satisfied       []string `json:"satisfied"`
	Missing         []string `json:"missing"`
	Contradictions  []string `json:"contradictions"`
	OperatorPhrase  string   `json:"operator_phrase"`
	Verdict         struct {
		VerdictTier      string   `json:"verdict_tier"`
		Reasons          []string `json:"reasons"`
		ModalityCoverage []string `json:"modality_coverage"`
		ObserverCoverage []string `json:"observer_coverage"`
		IndependentPair  []string `json:"independent_pair"`
	} `json:"verdict"`
}

// parseRankedHypotheses extracts ranking.hypotheses from the blob (string or
// already-parsed map). Returns nil for legacy pre-v1 blobs (bare arrays) and
// for anything unparsable — callers fall back, never fail.
func parseRankedHypotheses(raw any) []rankedHypothesis {
	var data []byte
	switch x := raw.(type) {
	case string:
		if strings.TrimSpace(x) == "" {
			return nil
		}
		data = []byte(x)
	case map[string]any:
		b, err := json.Marshal(x)
		if err != nil {
			return nil
		}
		data = b
	default:
		return nil
	}
	var blob struct {
		Ranking struct {
			Hypotheses []rankedHypothesis `json:"hypotheses"`
		} `json:"ranking"`
	}
	if err := json.Unmarshal(data, &blob); err != nil {
		return nil
	}
	return blob.Ranking.Hypotheses
}

// modalityNocLabel humanizes an engine modality class for NOC-facing AI text.
// Mirrors the ModalityClass enum values (signals.py) — when a class is added
// there, add its label here.
func modalityNocLabel(m string) string {
	switch m {
	case "active_probe":
		return "active probes"
	case "passive_flow":
		return "traffic flows"
	case "control_plane":
		return "control-plane events"
	case "device_telemetry":
		return "device telemetry"
	case "management_plane":
		return "controller (management plane)"
	default:
		return strings.ReplaceAll(m, "_", " ")
	}
}

// controllerKindNoc humanizes a normalized controller_* clause kind (the
// vendor-neutral kinds minted by controller_events.py / the nms transformers).
func controllerKindNoc(kind string) string {
	switch kind {
	case "controller_bfd_down":
		return "BFD session down"
	case "controller_tunnel_state":
		return "tunnel state change"
	case "controller_control_connection_loss":
		return "control-connection loss"
	case "controller_device_unreachable":
		return "device unreachable"
	case "controller_policy_change":
		return "configuration / policy change"
	case "controller_alarm":
		return "an active alarm"
	case "controller_health_score":
		return "health-score degradation"
	default:
		return strings.ReplaceAll(strings.TrimPrefix(kind, "controller_"), "_", " ")
	}
}

// splitControllerKinds partitions satisfied clause kinds into controller-
// reported vs directly-witnessed telemetry clauses. A clause kind can be a
// pipe-joined alternation ("controller_tunnel_state|controller_bfd_down") and
// the satisfied list records the expression, not which alternative matched —
// so a clause counts as controller only when EVERY alternative is controller_*
// and as direct only when NONE is; a mixed alternation proves neither and is
// dropped from both (never overclaim which witness fired).
func splitControllerKinds(satisfied []string) (controller, direct []string) {
	for _, k := range satisfied {
		alts := strings.Split(k, "|")
		ctrlAlts := 0
		for _, a := range alts {
			if strings.HasPrefix(strings.TrimSpace(a), "controller_") {
				ctrlAlts++
			}
		}
		switch ctrlAlts {
		case len(alts):
			controller = append(controller, k)
		case 0:
			direct = append(direct, k)
		}
	}
	return controller, direct
}

// controllerClauseNoc humanizes one satisfied controller clause, expanding a
// pipe alternation to "A / B" (either could have fired; show both).
func controllerClauseNoc(kind string) string {
	alts := strings.Split(kind, "|")
	out := make([]string, 0, len(alts))
	for _, a := range alts {
		out = append(out, controllerKindNoc(strings.TrimSpace(a)))
	}
	return strings.Join(out, " / ")
}

// rankedHypothesisItems renders the ranked hypotheses into cited evidence
// items: every candidate cause (bounded), and for the TOP hypothesis the
// evidence basis (modalities + independence), any controller-reported clauses
// with an explicit corroboration verdict, and contradictions. All wording is
// derived from persisted engine output — nothing is re-scored here.
func rankedHypothesisItems(id, href string, hyps []rankedHypothesis) []ai.EvidenceItem {
	var items []ai.EvidenceItem
	for i, h := range hyps {
		if i >= 5 {
			break
		}
		name := aiFirst(h.Title, h.ID)
		if strings.HasPrefix(name, "sig.") { // humanize the engine signature to NOC language
			name = noclabel.SignatureTitle(name)
		}
		if name == "" {
			continue
		}
		text := "candidate cause: " + name
		if h.ConfidenceLabel != "" {
			text += " — " + h.ConfidenceLabel
		} else if h.Confidence > 0 {
			text += fmt.Sprintf(" (score %.2f)", h.Confidence)
		}
		items = append(items, ai.EvidenceItem{
			CitationID: fmt.Sprintf("hypothesis:%s:%d", shortID(id), i),
			Kind:       "finding", Text: text, Href: href,
		})
		if i == 0 {
			items = append(items, topHypothesisEvidenceItems(id, href, h)...)
		}
	}
	return items
}

// topHypothesisEvidenceItems — the deep-dive items for the leading hypothesis:
// what the evidence basis is, what the controller reported (and whether direct
// telemetry corroborates it — the independence-gate story), and what
// contradicts. These are the citations behind "is this confirmed by telemetry
// or controller-only?".
func topHypothesisEvidenceItems(id, href string, h rankedHypothesis) []ai.EvidenceItem {
	var items []ai.EvidenceItem
	v := h.Verdict

	if len(v.ModalityCoverage) > 0 {
		labels := make([]string, 0, len(v.ModalityCoverage))
		for _, m := range v.ModalityCoverage {
			labels = append(labels, modalityNocLabel(m))
		}
		basis := "evidence basis: " + strings.Join(labels, ", ")
		switch {
		case len(v.IndependentPair) == 2:
			basis += fmt.Sprintf("; independently confirmed by %s and %s",
				noclabel.Entity(v.IndependentPair[0]), noclabel.Entity(v.IndependentPair[1]))
		case len(v.ModalityCoverage) == 1:
			basis += " — a single evidence stream cannot confirm on its own"
		}
		items = append(items, ai.EvidenceItem{
			CitationID: "evidence-basis:" + shortID(id), Kind: "finding",
			Text: basis, Href: href,
		})
	}

	if ctrl, direct := splitControllerKinds(h.Satisfied); len(ctrl) > 0 {
		reported := make([]string, 0, len(ctrl))
		for _, k := range ctrl {
			reported = append(reported, controllerClauseNoc(k))
		}
		text := "controller reported: " + strings.Join(reported, ", ")
		// The corroboration verdict comes from the gate's modality coverage (the
		// ground truth), with satisfied direct clauses as the fallback when an
		// older blob carries no coverage.
		mgmtOnly := len(v.ModalityCoverage) == 1 && v.ModalityCoverage[0] == "management_plane"
		hasDirectModality := false
		for _, m := range v.ModalityCoverage {
			if m != "management_plane" {
				hasDirectModality = true
			}
		}
		if hasDirectModality || (len(v.ModalityCoverage) == 0 && len(direct) > 0) {
			text += " — corroborated by direct telemetry (independent evidence streams agree)"
		} else if mgmtOnly || len(direct) == 0 {
			text += " — controller-only evidence; held at suspected until direct telemetry corroborates"
		}
		items = append(items, ai.EvidenceItem{
			CitationID: "controller:" + shortID(id), Kind: "finding",
			Text: text, Href: href,
		})
	}

	if h.Contradicted && len(h.Contradictions) > 0 {
		human := make([]string, 0, len(h.Contradictions))
		for _, k := range h.Contradictions {
			if ctrl, _ := splitControllerKinds([]string{k}); len(ctrl) == 1 {
				human = append(human, "controller view: "+controllerClauseNoc(k))
			} else {
				human = append(human, strings.ReplaceAll(strings.ReplaceAll(k, "|", " / "), "_", " "))
			}
		}
		items = append(items, ai.EvidenceItem{
			CitationID: "contradiction:" + shortID(id), Kind: "finding",
			Text: "contradicting evidence present: " + strings.Join(human, ", "), Href: href,
		})
	}
	return items
}
