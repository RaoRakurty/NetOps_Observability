package main

// rca_report_integrity.go — Phase 1 report immutability (postmortem spec
// "Additional mandatory" + §7): a generated document embeds an analysis
// snapshot hash, the policy and template versions, a content hash and the
// status-as-of record; a report revision is a NEW object in a per-case,
// tenant-scoped revision register. A published PDF is an immutable status
// snapshot — later ticket/analysis changes never mutate an existing revision;
// live status flows through the action register or a NEW revision.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/rca"
	"os"
	"strings"
	"sync"
	"time"
)

// The pure half — the ReportIntegrity block, ComputeReportIntegrity and the
// policy/template version constants — lives in internal/rca (rca_integrity.go).

// ---- revision register --------------------------------------------------------

// rcaReportRevision is ONE immutable generation record. A new generation whose
// analysis or content differs is a NEW revision; an identical regeneration
// reuses the existing revision (idempotent).
type rcaReportRevision struct {
	Revision  int                 `json:"revision"`
	ReportID  string              `json:"report_id"`
	Format    string              `json:"format"` // html | pdf
	Integrity rca.ReportIntegrity `json:"integrity"`
	CreatedAt string              `json:"created_at"`
	CreatedBy string              `json:"created_by"`
}

// rcaRevisionsMaxPerCase bounds the register (§9). When full, generation still
// works — the register just refuses NEW rows and the caller is told.
const rcaRevisionsMaxPerCase = 200

// rcaRevisionStore is a file-backed register keyed tenant → correlation id →
// ordered revisions. §3a rule 4: tenant key lives in the store itself; no
// unscoped listing exists.
type rcaRevisionStore struct {
	mu   sync.RWMutex
	m    map[string]map[string][]rcaReportRevision
	path string
}

func rcaRevisionsPath() string {
	if p := strings.TrimSpace(os.Getenv("RCA_REVISIONS_PATH")); p != "" {
		return p
	}
	return "/data/rca_report_revisions.json"
}

func newRcaRevisionStore(path string) *rcaRevisionStore {
	s := &rcaRevisionStore{m: map[string]map[string][]rcaReportRevision{}, path: path}
	if b, err := kvLoad(path); err == nil && len(b) > 0 {
		var m map[string]map[string][]rcaReportRevision
		if json.Unmarshal(b, &m) == nil {
			s.m = m
		}
	}
	return s
}

// F-62/F-63: returns error. A swallowed persist failure here made the
// handler above structurally unable to report that the write did not
// land — 200 with nothing saved. Callers roll back and answer 500.
func (s *rcaRevisionStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode rca revisions: %w", err)
	}
	if err := kvSave(s.path, b); err != nil {
		logError("rca", "persist rca revisions failed", map[string]any{"err": err.Error()})
		return fmt.Errorf("persist rca revisions: %w", err)
	}
	return nil
}

// list returns ONE tenant's revision register for one case, oldest first.
func (s *rcaRevisionStore) list(tenant, corrID string) []rcaReportRevision {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	revs := s.m[tenant][corrID]
	out := make([]rcaReportRevision, len(revs))
	copy(out, revs)
	return out
}

// record appends a NEW revision unless an existing one already carries the
// same analysis snapshot, content, template and policy (idempotent re-render).
// Returns the effective revision and whether it was newly created.
func (s *rcaRevisionStore) record(tenant, corrID string, rev rcaReportRevision) (rcaReportRevision, bool, error) {
	if s == nil {
		return rcaReportRevision{}, false, errors.New("revision store unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ex := range s.m[tenant][corrID] {
		if ex.Integrity.AnalysisSnapshotHash == rev.Integrity.AnalysisSnapshotHash &&
			ex.Integrity.ContentHash == rev.Integrity.ContentHash &&
			ex.Integrity.TemplateVersion == rev.Integrity.TemplateVersion &&
			ex.Integrity.PolicyVersion == rev.Integrity.PolicyVersion &&
			ex.Format == rev.Format {
			return ex, false, nil // identical regeneration — the revision is immutable and reused
		}
	}
	if len(s.m[tenant][corrID]) >= rcaRevisionsMaxPerCase {
		return rcaReportRevision{}, false, fmt.Errorf("revision register full for this case (max %d)", rcaRevisionsMaxPerCase)
	}
	if s.m[tenant] == nil {
		s.m[tenant] = map[string][]rcaReportRevision{}
	}
	rev.Revision = len(s.m[tenant][corrID]) + 1
	prev := s.m[tenant][corrID]
	s.m[tenant][corrID] = append(append([]rcaReportRevision(nil), prev...), rev)
	if err := s.saveLocked(); err != nil {
		// The register exists SPECIFICALLY to prove a report was not mutated. An
		// unpersisted revision must never be reported as registered.
		s.m[tenant][corrID] = prev
		return rcaReportRevision{}, false, err
	}
	return rev, true, nil
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
	revs := s.rcaRevisions.list(objTenant, id)
	writeJSON(w, http.StatusOK, map[string]any{
		"revisions": revs,
		"count":     len(revs),
		"note":      "each revision is immutable — a regenerated document with a changed analysis or template is a NEW revision; ticket changes after publication never mutate an existing one",
	})
}

// recordReportRevision computes+embeds nothing itself; it stores the register
// row for a document generation. Failures are logged, never fatal to the
// response (the document was already produced) — but they are observable.
func (s *server) recordReportRevision(claims jwtClaims, tenant, corrID string, rep rca.Report, integ rca.ReportIntegrity, format string) {
	if s.rcaRevisions == nil {
		return
	}
	_, _, err := s.rcaRevisions.record(tenant, corrID, rcaReportRevision{
		ReportID:  rep.ReportID,
		Format:    format,
		Integrity: integ,
		CreatedAt: rca.FmtUTC(time.Now().UTC()),
		CreatedBy: claims.Sub,
	})
	if err != nil {
		logWarn("rca", "record report revision failed", map[string]any{"correlation_id": corrID, "err": err.Error()})
	}
}
