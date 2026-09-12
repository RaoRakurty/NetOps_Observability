// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

// rca_emit.go — #81 Fusion Layer §L RCAEvidenceEmitter. Maps a fused identity onto the
// EXISTING Correlix evidence model (corr_evidence roles) so application identity becomes
// EVIDENCE/CONTEXT for the correlation engine — it never auto-establishes root cause.

// RCAEvidenceRole mirrors the correlation engine's evidence roles plus the
// concurrent/malformed buckets the spec calls out.
type RCAEvidenceRole string

const (
	RoleSupporting     RCAEvidenceRole = "supporting"
	RoleContradicting  RCAEvidenceRole = "contradicting"
	RoleDiscriminating RCAEvidenceRole = "discriminating"
	RoleConcurrent     RCAEvidenceRole = "concurrent" // present but not attributed to this object
	RoleMalformed      RCAEvidenceRole = "malformed"
)

// RCAEvidence is an app-identity evidence item to attach to a correlation object.
type RCAEvidence struct {
	CorrelationID  string          `json:"correlation_id"`
	FusionID       string          `json:"fusion_id"`
	App            string          `json:"app"`
	CanonicalAppID string          `json:"canonical_app_id,omitempty"`
	Role           RCAEvidenceRole `json:"role"`
	Band           ConfidenceBand  `json:"band"`
	State          ResolutionState `json:"state"`
	Note           string          `json:"note"`
}

// EmitRCAEvidence maps a fused identity → one RCA evidence item for a correlation.
// Conflicted identity contradicts (it weakens any single-app claim); unknown identity
// is concurrent context (present, unattributed); otherwise it supports.
func EmitRCAEvidence(fi FusedIdentity, correlationID string) RCAEvidence {
	role := RoleSupporting
	switch {
	case fi.State == StateConflicted:
		role = RoleContradicting
	case fi.App == "" || fi.App == "unknown":
		role = RoleConcurrent
	}
	return RCAEvidence{
		CorrelationID: correlationID, FusionID: fi.FusionID, App: fi.App,
		CanonicalAppID: fi.CanonicalAppID, Role: role, Band: fi.Band, State: fi.State,
		Note: BuildExplanation(fi).Conclusion,
	}
}

// AppImpactKind classifies the SHAPE of application impact across a shared path/seam —
// the cross-app inference that strengthens or weakens an infrastructure-fault hypothesis.
type AppImpactKind string

const (
	ImpactSharedInfra  AppImpactKind = "shared_infrastructure" // many unrelated apps fail on the same seam → infra fault stronger
	ImpactAppSpecific  AppImpactKind = "app_specific"          // one app fails while others stay healthy → app/provider issue
	ImpactInconclusive AppImpactKind = "inconclusive"
)

// AnalyzeSeamImpact classifies impact on a shared seam from the affected vs healthy
// apps that traverse it (§L). Application identity does NOT prove root cause; it shifts
// the WEIGHT of the infrastructure-vs-application hypothesis.
func AnalyzeSeamImpact(affected, healthy []string) AppImpactKind {
	a := len(distinct(affected))
	h := len(distinct(healthy))
	switch {
	case a >= 2:
		return ImpactSharedInfra // multiple unrelated apps failing on one path → shared infrastructure
	case a == 1 && h >= 1:
		return ImpactAppSpecific // one fails while others are healthy → app/provider-specific
	default:
		return ImpactInconclusive
	}
}
