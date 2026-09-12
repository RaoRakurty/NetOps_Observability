// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// rca_report_integrity_test.go — Phase 1 immutability (postmortem spec §7 +
// "Additional mandatory"): the embedded integrity block, snapshot-hash
// stability across re-renders of an unchanged analysis, the append-only
// tenant-keyed revision register, and the document-generation recording path.

import (
	"encoding/json"
	"fmt"
	"io"
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

// promoFakeCHSignals is promoFakeCHVerdict plus a window signal slice: the
// archive queries return one attached anomalous signal (the trigger), so the
// built report carries evidence-freshness (agoShort) and duration display
// strings — the wall-clock-derived content the minute-boundary contract pins.
// The bare promoFakeCH fixture has no signals, so nothing in its document
// drifts at minute granularity and a cross-minute test over it proves nothing.
func promoFakeCHSignals(t *testing.T, owner, verdict string) {
	t.Helper()
	metaRow := map[string]any{
		"version": "3", "tenant_id": owner, "state": "open", "merged_into": "",
		"window_start": "2026-07-12T18:10:00Z", "window_end": "2026-07-12T18:30:00Z",
		"trigger_signal": "00000000-0000-0000-0000-000000000000",
		"verdict_tier":   verdict, "top_hypothesis": "undetermined", "top_confidence": "0.4",
		"evidence_missing": "[]", "hypotheses": "{}", "affected": "{}",
		"layer_coverage": "{}", "app_impact": "{}", "attribution": "{}",
	}
	sigRow := map[string]any{
		"signal_id": "00000000-0000-0000-0000-000000000000",
		"ts_iso":    "2026-07-12T18:15:00Z", "ingest_ts_iso": "2026-07-12T18:15:01Z",
		"source": "snmp", "kind": "interface_down", "observer_type": "collector",
		"observer_id": "col-1", "collection_path": "poll", "modality_class": "network",
		"clock_quality": "ntp", "entity_type": "device", "entity_id": "core-sw1",
		"entity_tokens": []any{"core-sw1"}, "severity": "high",
		"value": "0", "baseline": "1", "deviation": "1", "metric_name": "ifOperStatus",
		"attrs": "{}", "onset_uncertainty_s": 0.0, "phase": "", "clear_ts": "",
		"probe_scope": "", "probe_authority": "", "classification_source": "",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sql := string(b)
		scope := r.URL.Query().Get("tenant_scope")
		w.Header().Set("Content-Type", "application/json")
		visible := scope == owner || scope == "__all__"
		answer := func(rows ...map[string]any) {
			enc, _ := json.Marshal(rows)
			_, _ = fmt.Fprintf(w, `{"meta":[],"data":%s,"rows":%d}`, enc, len(rows))
		}
		switch {
		case !visible:
			answer()
		case strings.Contains(sql, "SELECT tenant_id FROM netops.corr_objects"):
			answer(map[string]any{"tenant_id": owner})
		case strings.Contains(sql, "FROM netops.corr_objects"):
			answer(metaRow)
		case strings.Contains(sql, "max(archived_version)"):
			answer(map[string]any{"av": "1"})
		case strings.Contains(sql, "FROM netops.corr_signals_archive"):
			answer(sigRow)
		default: // corr_evidence, corr_edges, anything else
			answer()
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
}

// Cross-MINUTE regeneration. Re-stamping GeneratedAt/EscalationAt alone is not
// enough: agoShort freshness strings ("9m ago") and still-active elapsed
// durations are baked at BuildReport time with the FRESH clock. They are
// normalized OUT of the analysis snapshot hash, so the register still matches
// the prior revision — but once the clock crosses a minute boundary the
// rendered bytes drift anyway, and every later view appends a junk revision
// (the same spam the cross-second fix closed, one boundary up). The reuse path
// must REBUILD the report with the prior revision's generation stamp as its
// clock, so an unchanged analysis re-renders byte-identically at ANY later
// time. The clock is injected (s.rcaClock) — no 60-second sleeps.
func TestServeRcaReportRegenerationAcrossMinuteBoundaryIsIdempotent(t *testing.T) {
	// confirmed + a signal slice: the superset fixture — exercises the Decision
	// escalation stamp on top of the generation stamp AND the freshness/elapsed
	// display strings only attached evidence produces.
	promoFakeCHSignals(t, "acme", "confirmed")
	s := corrTestServer(t)
	s.rcaPromotions = newRcaPromotionStore("")
	s.rcaRevisions = newRcaRevisionStore("")
	_ = s.rcaPromotions.Set("acme", promoCorrID, rca.PromotionRecord{PromotedBy: "ops@acme", PromotedAt: "2026-07-18 12:00:00 UTC"})

	base := time.Now().UTC().Truncate(time.Second)
	clock := base
	s.rcaClock = func() time.Time { return clock }

	render := func() string {
		t.Helper()
		w := httptest.NewRecorder()
		s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report?format=html", "", acme()), promoCorrID)
		if w.Code != http.StatusOK {
			t.Fatalf("render = %d (%s)", w.Code, w.Body.String())
		}
		return w.Body.String()
	}

	first := render()
	if revs := s.rcaRevisions.List("acme", promoCorrID); len(revs) != 1 {
		t.Fatalf("first render must record exactly one revision: %+v", revs)
	}

	for _, adv := range []time.Duration{
		61 * time.Second, // crosses the minute boundary the cross-second test cannot see
		31 * time.Minute, // minute-scale agoShort drift ("9m ago" → "40m ago")
		26 * time.Hour,   // hour-scale drift + a different calendar day
	} {
		clock = base.Add(adv)
		if got := render(); got != first {
			t.Fatalf("unchanged analysis re-rendered %v later must be byte-identical (the document is a snapshot of the ANALYSIS, not of the wall clock)", adv)
		}
		if revs := s.rcaRevisions.List("acme", promoCorrID); len(revs) != 1 {
			t.Fatalf("re-render %v later appended a revision (wall-clock revision spam): %+v", adv, revs)
		}
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
