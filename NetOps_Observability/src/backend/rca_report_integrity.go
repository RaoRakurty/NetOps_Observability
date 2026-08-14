package backend

// rca_report_integrity.go — Phase 1 report immutability (postmortem spec
// "Additional mandatory" + §7): a generated document embeds an analysis
// snapshot hash, the policy and template versions, a content hash and the
// status-as-of record; a report revision is a NEW object in a per-case,
// tenant-scoped revision register. A published PDF is an immutable status
// snapshot — later ticket/analysis changes never mutate an existing revision;
// live status flows through the action register or a NEW revision.

import (
	"errors"
	"net/http"
	"netops/backend/internal/rca"
	"os"
	"strings"
	"time"
)

// The pure half — the ReportIntegrity block, ComputeReportIntegrity and the
// policy/template version constants — lives in internal/rca (rca_integrity.go).

// ---- revision register (internal/rca/revision_store.go, P2 RA.6) ------------

type (
	rcaReportRevision = rca.ReportRevision
	rcaRevisionStore  = rca.RevisionStore
)

func newRcaRevisionStore(path string) *rcaRevisionStore { return rca.NewRevisionStore(path) }

func rcaRevisionsPath() string {
	if p := strings.TrimSpace(os.Getenv("RCA_REVISIONS_PATH")); p != "" {
		return p
	}
	return "/data/rca_report_revisions.json"
}

// ---- HTTP ---------------------------------------------------------------------

// serveRcaRevisions serves GET /api/correlations/{id}/rca-revisions — the
// per-case revision register. Dispatched under requirePerm(infrastructure,
// read); the object is still resolved under the caller's ClickHouse tenant
// scope FIRST so a cross-tenant id answers 404 (§3a).
func (s *server) serveRcaRevisions(w http.ResponseWriter, r *http.Request, id string) {
	rows, err := s.chRowsScope(r.Context(), chTenantScope(r), `
SELECT tenant_id FROM netops.corr_objects
 WHERE correlation_id = '`+id+`'
 LIMIT 1
 FORMAT JSON`)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if len(rows) == 0 {
		writeError(w, http.StatusNotFound, errors.New("correlation object not found"))
		return
	}
	objTenant := canonicalCorrTenant(asString(rows[0]["tenant_id"]))
	revs := s.rcaRevisions.List(objTenant, id)
	writeJSON(w, http.StatusOK, map[string]any{
		"revisions": revs,
		"count":     len(revs),
		"note":      "each revision is immutable — a regenerated document with a changed analysis or template is a NEW revision; ticket changes after publication never mutate an existing one",
	})
}

// recordReportRevision computes+embeds nothing itself; it stores the register
// row for a document generation. A failure (register full, persist error) is
// returned to the caller, which FAILS the document request — the register
// exists to prove every served document is registered, so serving an
// unregistered immutable document on a swallowed error would defeat it. A nil
// store means the register is not configured (memory-only test servers) — not
// a Record failure.
func (s *server) recordReportRevision(claims jwtClaims, tenant, corrID string, rep rca.Report, integ rca.ReportIntegrity, format string) error {
	if s.rcaRevisions == nil {
		return nil
	}
	_, _, err := s.rcaRevisions.Record(tenant, corrID, rcaReportRevision{
		ReportID:  rep.ReportID,
		Format:    format,
		Integrity: integ,
		CreatedAt: rca.FmtUTC(time.Now().UTC()),
		CreatedBy: claims.Sub,
	})
	if err != nil {
		logWarn("rca", "record report revision failed", map[string]any{"correlation_id": corrID, "err": err.Error()})
	}
	return err
}
