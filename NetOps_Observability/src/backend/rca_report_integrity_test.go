package main

// rca_report_integrity_test.go — Phase 1 immutability (postmortem spec §7 +
// "Additional mandatory"): the embedded integrity block, snapshot-hash
// stability across re-renders of an unchanged analysis, the append-only
// tenant-keyed revision register, and the document-generation recording path.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func integrityReport(t *testing.T) rcaReport {
	t.Helper()
	meta := testMeta("closed", "suspected", "undetermined",
		testHyp("sig.x", 0.4, "suspected", []string{"probe_loss"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "prober->svc", "high", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss_clear", "active_probe", "prober", "path", "prober->svc", "info", "2026-07-12 18:15:15", false,
			map[string]any{"clear_ts": "2026-07-12 18:15:15"}),
	}
	return buildTestReport(t, meta, sigs)
}

func TestIntegrityBlockCompleteAndStable(t *testing.T) {
	rep := integrityReport(t)
	integ, err := computeReportIntegrity(rep)
	if err != nil {
		t.Fatalf("integrity: %v", err)
	}
	if !strings.HasPrefix(integ.AnalysisSnapshotHash, "sha256:") || len(integ.AnalysisSnapshotHash) != len("sha256:")+64 {
		t.Fatalf("snapshot hash malformed: %q", integ.AnalysisSnapshotHash)
	}
	if integ.PolicyVersion != rcaReportPolicyVersion || integ.TemplateVersion != rcaReportTemplateVersion {
		t.Fatalf("versions missing: %+v", integ)
	}
	if integ.StatusAsOf == "" || !strings.Contains(integ.StatusAsOf, "incident ") {
		t.Fatalf("status-as-of missing: %q", integ.StatusAsOf)
	}
	if integ.ContentHash != "" {
		t.Fatal("content hash must be set only when a document is rendered")
	}

	// The SAME analysis re-generated later hashes identically (generated-at and
	// freshness strings are normalized out) — the register can be idempotent.
	rep2 := rep
	rep2.GeneratedAt = fmtUTC(rcaTestNow.Add(45 * time.Minute))
	rep2.Evidence.LastObservation = "45m ago"
	integ2, err := computeReportIntegrity(rep2)
	if err != nil {
		t.Fatalf("integrity2: %v", err)
	}
	if integ2.AnalysisSnapshotHash != integ.AnalysisSnapshotHash {
		t.Fatal("unchanged analysis must keep its snapshot hash across re-renders")
	}

	// A CHANGED analysis is a different snapshot.
	rep3 := rep
	rep3.States.Analysis = "confirmed"
	integ3, _ := computeReportIntegrity(rep3)
	if integ3.AnalysisSnapshotHash == integ.AnalysisSnapshotHash {
		t.Fatal("a changed analysis must change the snapshot hash")
	}
}

func TestRevisionRegisterAppendOnlyAndIdempotent(t *testing.T) {
	st := newRcaRevisionStore("") // in-memory
	rep := integrityReport(t)
	integ, _ := computeReportIntegrity(rep)
	integ.ContentHash = hashContent([]byte("<html>doc v1</html>"))

	rev1, created, err := st.record("acme", "c-1", rcaReportRevision{ReportID: rep.ReportID, Format: "html", Integrity: integ, CreatedAt: "t1", CreatedBy: "a@acme"})
	if err != nil || !created || rev1.Revision != 1 {
		t.Fatalf("first record: %+v created=%v err=%v", rev1, created, err)
	}
	// Identical regeneration → the SAME immutable revision, no new object.
	rev1b, created, err := st.record("acme", "c-1", rcaReportRevision{ReportID: rep.ReportID, Format: "html", Integrity: integ, CreatedAt: "t2", CreatedBy: "b@acme"})
	if err != nil || created || rev1b.Revision != 1 || rev1b.CreatedAt != "t1" {
		t.Fatalf("identical regeneration must reuse revision 1 unchanged: %+v created=%v", rev1b, created)
	}
	// Changed content → a NEW revision object; revision 1 is never mutated.
	integ2 := integ
	integ2.ContentHash = hashContent([]byte("<html>doc v2</html>"))
	rev2, created, err := st.record("acme", "c-1", rcaReportRevision{ReportID: rep.ReportID, Format: "html", Integrity: integ2, CreatedAt: "t3", CreatedBy: "a@acme"})
	if err != nil || !created || rev2.Revision != 2 {
		t.Fatalf("changed content must append revision 2: %+v", rev2)
	}
	revs := st.list("acme", "c-1")
	if len(revs) != 2 || revs[0].Integrity.ContentHash != integ.ContentHash {
		t.Fatalf("register mutated: %+v", revs)
	}
}

func TestRevisionStoreIsTenantKeyed(t *testing.T) {
	st := newRcaRevisionStore("")
	rep := integrityReport(t)
	integ, _ := computeReportIntegrity(rep)
	if _, _, err := st.record("acme", "c-1", rcaReportRevision{Format: "html", Integrity: integ}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if got := st.list("globex", "c-1"); len(got) != 0 {
		t.Fatalf("TENANT LEAK: globex read acme's revision register: %+v", got)
	}
	if got := st.list("acme", "c-1"); len(got) != 1 {
		t.Fatalf("own register lost: %+v", got)
	}
}

// Document generation records a revision keyed by the OBJECT's owning tenant;
// the JSON tier embeds the integrity block without touching the register.
func TestServeRcaReportRecordsRevisionOnDocument(t *testing.T) {
	promoFakeCH(t, "acme")
	s := corrTestServer(t)
	s.rcaPromotions = newRcaPromotionStore("")
	s.rcaRevisions = newRcaRevisionStore("")
	_ = s.rcaPromotions.set("acme", promoCorrID, rcaPromotionRecord{PromotedBy: "ops@acme", PromotedAt: "2026-07-18 12:00:00 UTC"})

	// JSON: integrity embedded, no revision recorded.
	w := httptest.NewRecorder()
	s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report", "", acme()), promoCorrID)
	if w.Code != http.StatusOK {
		t.Fatalf("json = %d (%s)", w.Code, w.Body.String())
	}
	var rep struct {
		Integrity *rcaReportIntegrity `json:"integrity"`
	}
	if err := json.NewDecoder(w.Body).Decode(&rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep.Integrity == nil || rep.Integrity.AnalysisSnapshotHash == "" {
		t.Fatalf("json response must embed the integrity block: %+v", rep.Integrity)
	}
	if got := s.rcaRevisions.list("acme", promoCorrID); len(got) != 0 {
		t.Fatalf("json read must not create revisions: %+v", got)
	}

	// HTML document: revision recorded under the OBJECT's tenant with content hash.
	w = httptest.NewRecorder()
	s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report?format=html", "", acme()), promoCorrID)
	if w.Code != http.StatusOK {
		t.Fatalf("html = %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Analysis snapshot sha256:") {
		t.Fatal("rendered document must embed the integrity footer")
	}
	revs := s.rcaRevisions.list("acme", promoCorrID)
	if len(revs) != 1 || revs[0].Format != "html" || !strings.HasPrefix(revs[0].Integrity.ContentHash, "sha256:") {
		t.Fatalf("document revision not recorded: %+v", revs)
	}
	if revs[0].CreatedBy != "a@acme" {
		t.Fatalf("revision must record who generated it: %+v", revs[0])
	}

	// Regenerating the same document appends nothing (idempotent register).
	w = httptest.NewRecorder()
	s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report?format=html", "", acme()), promoCorrID)
	if w.Code != http.StatusOK {
		t.Fatalf("html regen = %d", w.Code)
	}
	if revs := s.rcaRevisions.list("acme", promoCorrID); len(revs) != 1 {
		t.Fatalf("identical regeneration duplicated the revision: %+v", revs)
	}
}

// The revision register endpoint honors §3a: cross-tenant id → 404.
func TestRcaRevisionsEndpointTenantScoped(t *testing.T) {
	promoFakeCH(t, "acme")
	s := corrTestServer(t)
	s.rcaRevisions = newRcaRevisionStore("")
	rep := integrityReport(t)
	integ, _ := computeReportIntegrity(rep)
	if _, _, err := s.rcaRevisions.record("acme", promoCorrID, rcaReportRevision{Format: "html", Integrity: integ}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := httptest.NewRecorder()
	s.serveRcaRevisions(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-revisions", "", acme()), promoCorrID)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "sha256:") {
		t.Fatalf("own-tenant list = %d (%s)", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	s.serveRcaRevisions(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-revisions", "", globex()), promoCorrID)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant list = %d, want 404", w.Code)
	}
}
