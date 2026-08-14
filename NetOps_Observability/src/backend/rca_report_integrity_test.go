package backend

// rca_report_integrity_test.go — Phase 1 immutability (postmortem spec §7 +
// "Additional mandatory"): the embedded integrity block, snapshot-hash
// stability across re-renders of an unchanged analysis, the append-only
// tenant-keyed revision register, and the document-generation recording path.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/rca"
	"strings"
	"testing"
	"time"
)

// integrityReport builds a minimal report for the register tests — the store
// cares about hashes and revisions, not report semantics; the full-builder
// integrity-stability contract lives in internal/rca (rca_integrity_test.go).
func integrityReport(t *testing.T) rca.Report {
	t.Helper()
	rep := rca.Report{ReportID: "RCA-test-1", GeneratedAt: "2026-07-12 20:00:00 UTC"}
	return rep
}

func TestRevisionRegisterAppendOnlyAndIdempotent(t *testing.T) {
	st := newRcaRevisionStore("") // in-memory
	rep := integrityReport(t)
	integ, _ := rca.ComputeReportIntegrity(rep)
	integ.ContentHash = rca.HashContent([]byte("<html>doc v1</html>"))

	rev1, created, err := st.Record("acme", "c-1", rcaReportRevision{ReportID: rep.ReportID, Format: "html", Integrity: integ, CreatedAt: "t1", CreatedBy: "a@acme"})
	if err != nil || !created || rev1.Revision != 1 {
		t.Fatalf("first record: %+v created=%v err=%v", rev1, created, err)
	}
	// Identical regeneration → the SAME immutable revision, no new object.
	rev1b, created, err := st.Record("acme", "c-1", rcaReportRevision{ReportID: rep.ReportID, Format: "html", Integrity: integ, CreatedAt: "t2", CreatedBy: "b@acme"})
	if err != nil || created || rev1b.Revision != 1 || rev1b.CreatedAt != "t1" {
		t.Fatalf("identical regeneration must reuse revision 1 unchanged: %+v created=%v", rev1b, created)
	}
	// Changed content → a NEW revision object; revision 1 is never mutated.
	integ2 := integ
	integ2.ContentHash = rca.HashContent([]byte("<html>doc v2</html>"))
	rev2, created, err := st.Record("acme", "c-1", rcaReportRevision{ReportID: rep.ReportID, Format: "html", Integrity: integ2, CreatedAt: "t3", CreatedBy: "a@acme"})
	if err != nil || !created || rev2.Revision != 2 {
		t.Fatalf("changed content must append revision 2: %+v", rev2)
	}
	revs := st.List("acme", "c-1")
	if len(revs) != 2 || revs[0].Integrity.ContentHash != integ.ContentHash {
		t.Fatalf("register mutated: %+v", revs)
	}
}

func TestRevisionStoreIsTenantKeyed(t *testing.T) {
	st := newRcaRevisionStore("")
	rep := integrityReport(t)
	integ, _ := rca.ComputeReportIntegrity(rep)
	if _, _, err := st.Record("acme", "c-1", rcaReportRevision{Format: "html", Integrity: integ}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if got := st.List("globex", "c-1"); len(got) != 0 {
		t.Fatalf("TENANT LEAK: globex read acme's revision register: %+v", got)
	}
	if got := st.List("acme", "c-1"); len(got) != 1 {
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
	_ = s.rcaPromotions.Set("acme", promoCorrID, rca.PromotionRecord{PromotedBy: "ops@acme", PromotedAt: "2026-07-18 12:00:00 UTC"})

	// JSON: integrity embedded, no revision recorded.
	w := httptest.NewRecorder()
	s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report", "", acme()), promoCorrID)
	if w.Code != http.StatusOK {
		t.Fatalf("json = %d (%s)", w.Code, w.Body.String())
	}
	var rep struct {
		Integrity *rca.ReportIntegrity `json:"integrity"`
	}
	if err := json.NewDecoder(w.Body).Decode(&rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep.Integrity == nil || rep.Integrity.AnalysisSnapshotHash == "" {
		t.Fatalf("json response must embed the integrity block: %+v", rep.Integrity)
	}
	if got := s.rcaRevisions.List("acme", promoCorrID); len(got) != 0 {
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
	revs := s.rcaRevisions.List("acme", promoCorrID)
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
	if revs := s.rcaRevisions.List("acme", promoCorrID); len(revs) != 1 {
		t.Fatalf("identical regeneration duplicated the revision: %+v", revs)
	}
}

// Regenerating an UNCHANGED analysis in a LATER wall-clock second must still
// reuse the existing revision. The rendered document embeds its generation
// timestamp, so a naive re-render across a second boundary produces different
// bytes → different content hash → a junk revision per view until the
// register hits RevisionsMaxPerCase (surfaced as a rare -race CI failure of
// TestServeRcaReportRecordsRevisionOnDocument, 2026-08-12). The fix renders
// with the ORIGINAL revision's generation stamp when the analysis is
// unchanged, reproducing revision N byte-for-byte.
func TestServeRcaReportRegenerationAcrossSecondsIsIdempotent(t *testing.T) {
	promoFakeCH(t, "acme")
	s := corrTestServer(t)
	s.rcaPromotions = newRcaPromotionStore("")
	s.rcaRevisions = newRcaRevisionStore("")
	_ = s.rcaPromotions.Set("acme", promoCorrID, rca.PromotionRecord{PromotedBy: "ops@acme", PromotedAt: "2026-07-18 12:00:00 UTC"})

	w := httptest.NewRecorder()
	s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report?format=html", "", acme()), promoCorrID)
	if w.Code != http.StatusOK {
		t.Fatalf("first render = %d (%s)", w.Code, w.Body.String())
	}
	first := w.Body.String()
	revs := s.rcaRevisions.List("acme", promoCorrID)
	if len(revs) != 1 {
		t.Fatalf("first render must record exactly one revision: %+v", revs)
	}

	// Force the re-render into a DIFFERENT wall-clock second — the exact
	// window the naive implementation loses.
	now := time.Now()
	time.Sleep(time.Until(now.Truncate(time.Second).Add(time.Second + 50*time.Millisecond)))

	w = httptest.NewRecorder()
	s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report?format=html", "", acme()), promoCorrID)
	if w.Code != http.StatusOK {
		t.Fatalf("re-render = %d (%s)", w.Code, w.Body.String())
	}
	if w.Body.String() != first {
		t.Fatal("unchanged analysis must re-render byte-identically (the document is a snapshot of the ANALYSIS, not of the wall clock)")
	}
	if revs := s.rcaRevisions.List("acme", promoCorrID); len(revs) != 1 {
		t.Fatalf("cross-second regeneration duplicated the revision: %+v", revs)
	}
}

// A CONFIRMED case stamps Decision.EscalationAt ("TRIGGERED at <generation
// stamp>") into the rendered document. Like GeneratedAt it is generation-clock
// display, not analysis: re-rendering the unchanged analysis in a later second
// must reproduce the existing revision byte-for-byte — not hash a fresh
// escalation stamp into a new snapshot + revision on every view.
func TestServeRcaReportConfirmedCaseCrossSecondIdempotent(t *testing.T) {
	promoFakeCHVerdict(t, "acme", "confirmed")
	s := corrTestServer(t)
	s.rcaPromotions = newRcaPromotionStore("")
	s.rcaRevisions = newRcaRevisionStore("")
	_ = s.rcaPromotions.Set("acme", promoCorrID, rca.PromotionRecord{PromotedBy: "ops@acme", PromotedAt: "2026-07-18 12:00:00 UTC"})

	w := httptest.NewRecorder()
	s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report?format=html", "", acme()), promoCorrID)
	if w.Code != http.StatusOK {
		t.Fatalf("first render = %d (%s)", w.Code, w.Body.String())
	}
	first := w.Body.String()
	if !strings.Contains(first, "TRIGGERED at ") {
		t.Fatal("fixture must render a triggered escalation stamp (confirmed analysis)")
	}
	if revs := s.rcaRevisions.List("acme", promoCorrID); len(revs) != 1 {
		t.Fatalf("first render must record exactly one revision: %+v", revs)
	}

	// Cross into a DIFFERENT wall-clock second.
	now := time.Now()
	time.Sleep(time.Until(now.Truncate(time.Second).Add(time.Second + 50*time.Millisecond)))

	w = httptest.NewRecorder()
	s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report?format=html", "", acme()), promoCorrID)
	if w.Code != http.StatusOK {
		t.Fatalf("re-render = %d (%s)", w.Code, w.Body.String())
	}
	if w.Body.String() != first {
		t.Fatal("unchanged CONFIRMED analysis must re-render byte-identically (EscalationAt is generation-clock display, not analysis)")
	}
	if revs := s.rcaRevisions.List("acme", promoCorrID); len(revs) != 1 {
		t.Fatalf("confirmed-case re-render appended a revision (escalation-stamp revision spam): %+v", revs)
	}
}

// PDF bytes from the Gotenberg sidecar are NONDETERMINISTIC (random /ID,
// CreationDate): hashing them makes every download a "new" revision. A pdf
// revision instead attests the DETERMINISTIC HTML source document fed to the
// sidecar, so identical analyses dedupe; the served PDF stays the sidecar's
// output.
func TestServeRcaReportPDFRevisionAttestsSourceDocument(t *testing.T) {
	promoFakeCH(t, "acme")
	// Fake sidecar: different bytes on every conversion, like real Gotenberg.
	n := 0
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		w.Header().Set("Content-Type", "application/pdf")
		fmt.Fprintf(w, "%%PDF-1.4 fake body, conversion %d", n)
	}))
	t.Cleanup(sidecar.Close)
	t.Setenv("REPORT_PDF_SIDECAR_URL", sidecar.URL)

	s := corrTestServer(t)
	s.rcaPromotions = newRcaPromotionStore("")
	s.rcaRevisions = newRcaRevisionStore("")
	_ = s.rcaPromotions.Set("acme", promoCorrID, rca.PromotionRecord{PromotedBy: "ops@acme", PromotedAt: "2026-07-18 12:00:00 UTC"})

	get := func() string {
		w := httptest.NewRecorder()
		s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report?format=pdf", "", acme()), promoCorrID)
		if w.Code != http.StatusOK {
			t.Fatalf("pdf = %d (%s)", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	pdf1 := get()
	pdf2 := get()
	if pdf1 == pdf2 {
		t.Fatal("fixture defect: sidecar must produce nondeterministic bytes")
	}
	revs := s.rcaRevisions.List("acme", promoCorrID)
	if len(revs) != 1 {
		t.Fatalf("re-downloading an unchanged analysis as PDF must reuse the revision, got %d revisions (nondeterministic sidecar bytes were hashed): %+v", len(revs), revs)
	}
	ch := revs[0].Integrity.ContentHash
	if !strings.HasPrefix(ch, "sha256:") {
		t.Fatalf("pdf revision content hash malformed: %q", ch)
	}
	if ch == rca.HashContent([]byte(pdf1)) || ch == rca.HashContent([]byte(pdf2)) {
		t.Fatal("pdf revision must attest the deterministic HTML source document, not the sidecar's nondeterministic output bytes")
	}
}

// The register's whole point is that a served document IS registered. When the
// register refuses the row (full) or cannot persist it, the DOCUMENT request
// must fail — never silently serve an unregistered immutable document. The
// JSON tier never touches the register and stays readable.
func TestServeRcaReportFailsClosedWhenRegisterFull(t *testing.T) {
	promoFakeCH(t, "acme")
	s := corrTestServer(t)
	s.rcaPromotions = newRcaPromotionStore("")
	s.rcaRevisions = newRcaRevisionStore("")
	_ = s.rcaPromotions.Set("acme", promoCorrID, rca.PromotionRecord{PromotedBy: "ops@acme", PromotedAt: "2026-07-18 12:00:00 UTC"})

	// Fill the per-case register to its bound with distinct revisions.
	for i := 0; i < rca.RevisionsMaxPerCase; i++ {
		integ := rca.ReportIntegrity{
			AnalysisSnapshotHash: fmt.Sprintf("sha256:%064d", i),
			ContentHash:          fmt.Sprintf("sha256:%064d", i),
			PolicyVersion:        rca.ReportPolicyVersion,
			TemplateVersion:      rca.ReportTemplateVersion,
		}
		if _, _, err := s.rcaRevisions.Record("acme", promoCorrID, rcaReportRevision{Format: "html", Integrity: integ}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	w := httptest.NewRecorder()
	s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report?format=html", "", acme()), promoCorrID)
	if w.Code < 500 {
		t.Fatalf("document render with a refusing register = %d, want 5xx — an immutable document must never be served unregistered (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(strings.ToLower(w.Body.String()), "register") {
		t.Fatalf("error must name the revision register: %s", w.Body.String())
	}

	// JSON tier (workspace data) is untouched by the register.
	w = httptest.NewRecorder()
	s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report", "", acme()), promoCorrID)
	if w.Code != http.StatusOK {
		t.Fatalf("json with full register = %d, want 200", w.Code)
	}
}

// The revision register endpoint honors §3a: cross-tenant id → 404.
func TestRcaRevisionsEndpointTenantScoped(t *testing.T) {
	promoFakeCH(t, "acme")
	s := corrTestServer(t)
	s.rcaRevisions = newRcaRevisionStore("")
	rep := integrityReport(t)
	integ, _ := rca.ComputeReportIntegrity(rep)
	if _, _, err := s.rcaRevisions.Record("acme", promoCorrID, rcaReportRevision{Format: "html", Integrity: integ}); err != nil {
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
