package rca

// rca_integrity.go — the pure half of Phase 1 report immutability (postmortem
// spec "Additional mandatory" + §7): the integrity block a generated document
// embeds and its derivation. The per-case, tenant-scoped revision REGISTER
// (file-backed store + HTTP) stays with the integrator in package main.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ReportPolicyVersion names the honesty/derivation policy that produced the
// report — bump when promotion criteria or state-derivation rules change.
const ReportPolicyVersion = "rca-policy-2026.07.19-p1"

// ReportIntegrity is the immutability block a generated document embeds.
type ReportIntegrity struct {
	// AnalysisSnapshotHash: sha256 over the canonical report JSON with
	// volatile generation-time display fields normalized — it identifies the
	// ANALYSIS the document was generated from.
	AnalysisSnapshotHash string `json:"analysis_snapshot_hash"`
	PolicyVersion        string `json:"policy_version"`
	TemplateVersion      string `json:"template_version"`
	// ContentHash: sha256 of the rendered artifact bytes. Set only when a
	// document (html/pdf source) was actually rendered.
	ContentHash string `json:"content_hash,omitempty"`
	GeneratedAt string `json:"generated_at"`
	// StatusAsOf: the workflow states AT generation time — a published
	// document is a snapshot "as of", never a live view.
	StatusAsOf string `json:"status_as_of"`
}

// ComputeReportIntegrity derives the integrity block from a finished report.
// Volatile fields that change with the wall clock but not the analysis
// (generated-at, freshness strings, still-active elapsed duration) are
// normalized so re-rendering an unchanged analysis yields the same hash.
func ComputeReportIntegrity(rep Report) (ReportIntegrity, error) {
	cp := rep
	cp.GeneratedAt = ""
	cp.Integrity = nil
	cp.Evidence.LastObservation = ""
	// The quality gate's evaluation stamp is generation-time metadata, exactly
	// like GeneratedAt. Unnormalized it broke the revision register's
	// idempotency whenever two identical renders straddled a second boundary
	// (latent since Phase 1; surfaced by the wave-2 move's test runs).
	cp.Quality.EvaluatedAt = ""
	if cp.Times.DurationBasis == "elapsed_still_active" {
		cp.Times.DurationMS = 0
	}
	b, err := json.Marshal(cp)
	if err != nil {
		return ReportIntegrity{}, fmt.Errorf("integrity snapshot marshal: %w", err)
	}
	sum := sha256.Sum256(b)
	return ReportIntegrity{
		AnalysisSnapshotHash: "sha256:" + hex.EncodeToString(sum[:]),
		PolicyVersion:        ReportPolicyVersion,
		TemplateVersion:      ReportTemplateVersion,
		GeneratedAt:          rep.GeneratedAt,
		StatusAsOf: fmt.Sprintf("incident %s · analysis %s · impact %s · ticket %s · promotion %s · class %s",
			rep.States.Incident, rep.States.Analysis, rep.States.Impact,
			rep.States.Ticket, orDefault(rep.Promotion.Basis, "not_promoted"), rep.Maturity.Class),
	}, nil
}

// HashContent hashes rendered artifact bytes for the ContentHash slot.
func HashContent(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
