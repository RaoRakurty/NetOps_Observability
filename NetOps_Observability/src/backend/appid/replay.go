// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

// replay.go — #81 Fusion Layer §M ReplayEngine. Recompute identity deterministically
// on late evidence / catalog or parser update / override change / manual or audit
// request. NEVER mutates a historical fused result — produces a NEW versioned result
// (the fusion id is keyed on catalog+engine version) and surfaces the drift.

// ReplayReason records WHY a replay happened (audited).
type ReplayReason string

const (
	ReplayLateEvidence   ReplayReason = "late_evidence"
	ReplayCatalogUpdate  ReplayReason = "catalog_update"
	ReplayParserUpdate   ReplayReason = "parser_update"
	ReplayOverrideChange ReplayReason = "override_change"
	ReplayManual         ReplayReason = "manual"
	ReplayAudit          ReplayReason = "audit"
)

// ReplayResult is a versioned recomputation: the OLD result is preserved verbatim, a
// NEW one is produced, and the decision drift is reported.
type ReplayResult struct {
	Reason  ReplayReason  `json:"reason"`
	Old     FusedIdentity `json:"old"`
	New     FusedIdentity `json:"new"`
	Changed bool          `json:"changed"` // did app / band / state change?
}

// ReplayFusion recomputes the fusion with (possibly) new observations/policy/catalog,
// preserving old. Deterministic: same inputs → same New (and re-running with the SAME
// catalog version reproduces the historical decision bit-for-bit).
func ReplayFusion(old FusedIdentity, in FuseInput, reason ReplayReason) ReplayResult {
	nw := FuseObservations(in)
	if reason == ReplayLateEvidence && !codeContains(nw.Explanations, ExLateEvidenceReplay) {
		nw.Explanations = append(nw.Explanations, ExLateEvidenceReplay)
	}
	changed := nw.App != old.App || nw.Band != old.Band || nw.State != old.State
	return ReplayResult{Reason: reason, Old: old, New: nw, Changed: changed}
}

func codeContains(codes []ExplanationCode, c ExplanationCode) bool {
	for _, x := range codes {
		if x == c {
			return true
		}
	}
	return false
}
