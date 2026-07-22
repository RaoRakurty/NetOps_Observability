package main

// rca_promotion_test.go — #113 point 3: RCA documents are a promoted tier, not
// every candidate. Covers: the auto-promotion criteria (confirmed verdict ·
// confirmed user/app impact · duration · production), the manual override, the
// html/pdf document gate (JSON/workspace tier always readable), and the §3a
// isolation contract of the promotion subresource (cross-tenant id → 404,
// records keyed by the OBJECT's owning tenant, writes audited-path-only).

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---- evaluation --------------------------------------------------------------

func promoReport(analysis, impact string, dur time.Duration, validation bool) rcaReport {
	return rcaReport{
		Validation: validation,
		States:     rcaReportStates{Analysis: analysis, Impact: impact, ImpactRealUser: "unknown", ImpactSynthetic: "confirmed"},
		Times:      rcaReportTimes{DurationMS: dur.Milliseconds()},
	}
}

func TestPromotionAutoRequiresAllCriteria(t *testing.T) {
	rep := promoReport("confirmed", "confirmed", 10*time.Minute, false)
	st := evaluateRcaPromotion(&rep, nil)
	if !st.Promoted || st.Basis != "auto" {
		t.Fatalf("real outage must auto-promote: %+v", st)
	}

	for name, r := range map[string]rcaReport{
		"unconfirmed verdict": promoReport("suspected", "confirmed", 10*time.Minute, false),
		"no user impact":      promoReport("confirmed", "detected", 10*time.Minute, false),
		"blip duration":       promoReport("confirmed", "confirmed", 90*time.Second, false),
		"validation scenario": promoReport("confirmed", "confirmed", 10*time.Minute, true),
	} {
		rr := r
		st := evaluateRcaPromotion(&rr, nil)
		if st.Promoted {
			t.Fatalf("%s must NOT auto-promote: %+v", name, st)
		}
		if st.Basis != "not_promoted" || !strings.Contains(st.Reason, "reserved for promoted real outages") {
			t.Fatalf("%s: refusal must explain the policy: %+v", name, st)
		}
	}
}

func TestPromotionManualOverrides(t *testing.T) {
	rep := promoReport("suspected", "detected", time.Minute, false)
	rec := &rcaPromotionRecord{PromotedBy: "ops@acme", PromotedAt: "2026-07-18 12:00:00 UTC"}
	st := evaluateRcaPromotion(&rep, rec)
	if !st.Promoted || st.Basis != "manual" || !strings.Contains(st.Reason, "ops@acme") {
		t.Fatalf("manual promotion must win with attribution: %+v", st)
	}
}

// ---- store ------------------------------------------------------------------

func TestPromotionStoreIsTenantKeyed(t *testing.T) {
	st := newRcaPromotionStore("") // in-memory
	_ = st.set("acme", "c-1", rcaPromotionRecord{PromotedBy: "a"})
	if _, ok := st.get("globex", "c-1"); ok {
		t.Fatal("TENANT LEAK: another tenant read acme's promotion")
	}
	if rec, ok := st.get("acme", "c-1"); !ok || rec.PromotedBy != "a" {
		t.Fatalf("own record lost: %+v ok=%v", rec, ok)
	}
	_ = st.remove("acme", "c-1")
	if _, ok := st.get("acme", "c-1"); ok {
		t.Fatal("remove did not delete")
	}
}

// ---- HTTP: fake CH that emulates the corr_objects row policy ----------------

const promoCorrID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

// promoFakeCH serves the tenant-scoped reads serveRcaReport/handleRcaPromotion
// issue. The object belongs to `owner`; a scope that is neither the owner nor
// __all__ sees NO rows — exactly what the ClickHouse row policy enforces.
func promoFakeCH(t *testing.T, owner string) {
	t.Helper()
	metaRow := map[string]any{
		"version": "3", "tenant_id": owner, "state": "open", "merged_into": "",
		"window_start": "2026-07-12T18:10:00Z", "window_end": "2026-07-12T18:30:00Z",
		"trigger_signal": "00000000-0000-0000-0000-000000000000",
		"verdict_tier":   "suspected", "top_hypothesis": "undetermined", "top_confidence": "0.4",
		"evidence_missing": "[]", "hypotheses": "{}", "affected": "{}",
		"layer_coverage": "{}", "app_impact": "{}", "attribution": "{}",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sql := string(b)
		scope := r.URL.Query().Get("tenant_scope")
		w.Header().Set("Content-Type", "application/json")
		visible := scope == owner || scope == "__all__"
		if visible && strings.Contains(sql, "FROM netops.corr_objects") {
			var row []byte
			if strings.Contains(sql, "SELECT tenant_id FROM netops.corr_objects") {
				row, _ = json.Marshal(map[string]any{"tenant_id": owner})
			} else {
				row, _ = json.Marshal(metaRow)
			}
			_, _ = w.Write([]byte(`{"meta":[],"data":[` + string(row) + `],"rows":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
}

func promoServer(t *testing.T) *server {
	t.Helper()
	s := corrTestServer(t)
	s.rcaPromotions = newRcaPromotionStore("")
	return s
}

// ---- HTTP: the promotion subresource (§3a isolation) ------------------------

func TestPromoteOwnTenantAndKeyedByOwner(t *testing.T) {
	promoFakeCH(t, "acme")
	s := promoServer(t)

	w := httptest.NewRecorder()
	s.handleRcaPromotion(w, req(http.MethodPost, "/api/correlations/"+promoCorrID+"/rca-promotion", `{"note":"C-suite outage review"}`, acme()), promoCorrID)
	if w.Code != http.StatusOK {
		t.Fatalf("own-tenant promote = %d (%s)", w.Code, w.Body.String())
	}
	rec, ok := s.rcaPromotions.get("acme", promoCorrID)
	if !ok || rec.PromotedBy != "a@acme" || rec.Note != "C-suite outage review" {
		t.Fatalf("record not stored under the owning tenant: %+v ok=%v", rec, ok)
	}

	// GET reads it back with read permission only.
	w = httptest.NewRecorder()
	s.handleRcaPromotion(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-promotion", "", acme()), promoCorrID)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"manually_promoted":true`) {
		t.Fatalf("status read-back = %d (%s)", w.Code, w.Body.String())
	}

	// DELETE revokes.
	w = httptest.NewRecorder()
	s.handleRcaPromotion(w, req(http.MethodDelete, "/api/correlations/"+promoCorrID+"/rca-promotion", "", acme()), promoCorrID)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke = %d", w.Code)
	}
	if _, ok := s.rcaPromotions.get("acme", promoCorrID); ok {
		t.Fatal("revoked promotion still stored")
	}
}

func TestPromoteCrossTenantIs404(t *testing.T) {
	promoFakeCH(t, "acme")
	s := promoServer(t)

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		w := httptest.NewRecorder()
		s.handleRcaPromotion(w, req(method, "/api/correlations/"+promoCorrID+"/rca-promotion", "", globex()), promoCorrID)
		if w.Code != http.StatusNotFound {
			t.Fatalf("cross-tenant %s = %d, want 404 (never reveal the id)", method, w.Code)
		}
	}
	if _, ok := s.rcaPromotions.get("acme", promoCorrID); ok {
		t.Fatal("cross-tenant call must never write the owner's store")
	}
	if _, ok := s.rcaPromotions.get("globex", promoCorrID); ok {
		t.Fatal("cross-tenant call must never create a foreign record")
	}
}

func TestPromoteCrossScopeAdminKeysByObjectTenant(t *testing.T) {
	promoFakeCH(t, "acme")
	s := promoServer(t)

	w := httptest.NewRecorder()
	s.handleRcaPromotion(w, req(http.MethodPost, "/api/correlations/"+promoCorrID+"/rca-promotion", "", superA()), promoCorrID)
	if w.Code != http.StatusOK {
		t.Fatalf("platform admin promote = %d (%s)", w.Code, w.Body.String())
	}
	// Stamped by the OBJECT's owning tenant — never by the admin's (absent) one.
	if _, ok := s.rcaPromotions.get("acme", promoCorrID); !ok {
		t.Fatal("promotion must key by the object's owning tenant")
	}
}

func TestPromoteRejectsOversizeNote(t *testing.T) {
	promoFakeCH(t, "acme")
	s := promoServer(t)
	body, _ := json.Marshal(map[string]string{"note": strings.Repeat("x", 501)})
	w := httptest.NewRecorder()
	s.handleRcaPromotion(w, req(http.MethodPost, "/api/correlations/"+promoCorrID+"/rca-promotion", string(body), acme()), promoCorrID)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversize note = %d, want 400", w.Code)
	}
}

// ---- HTTP: the document gate ------------------------------------------------

func TestRcaDocumentGateBlocksUnpromotedHTML(t *testing.T) {
	promoFakeCH(t, "acme")
	s := promoServer(t)

	// JSON (workspace tier) stays readable and carries the promotion status.
	w := httptest.NewRecorder()
	s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report", "", acme()), promoCorrID)
	if w.Code != http.StatusOK {
		t.Fatalf("candidate JSON = %d (%s)", w.Code, w.Body.String())
	}
	var rep struct {
		Promotion rcaPromotionStatus `json:"promotion"`
	}
	if err := json.NewDecoder(w.Body).Decode(&rep); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rep.Promotion.Promoted || rep.Promotion.Basis != "not_promoted" {
		t.Fatalf("suspected 20-minute candidate must not be promoted: %+v", rep.Promotion)
	}

	// The DOCUMENT is refused with the policy reason.
	w = httptest.NewRecorder()
	s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report?format=html", "", acme()), promoCorrID)
	if w.Code != http.StatusForbidden {
		t.Fatalf("un-promoted html = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "reserved for promoted real outages") {
		t.Fatalf("refusal must explain the policy: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report?format=pdf", "", acme()), promoCorrID)
	if w.Code != http.StatusForbidden {
		t.Fatalf("un-promoted pdf = %d, want 403", w.Code)
	}
}

func TestRcaDocumentGateOpensAfterManualPromotion(t *testing.T) {
	promoFakeCH(t, "acme")
	s := promoServer(t)
	_ = s.rcaPromotions.set("acme", promoCorrID, rcaPromotionRecord{PromotedBy: "ops@acme", PromotedAt: "2026-07-18 12:00:00 UTC"})

	w := httptest.NewRecorder()
	s.serveRcaReport(w, req(http.MethodGet, "/api/correlations/"+promoCorrID+"/rca-report?format=html", "", acme()), promoCorrID)
	if w.Code != http.StatusOK {
		t.Fatalf("promoted html = %d (%s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q", ct)
	}
	if !strings.Contains(w.Body.String(), "Incident at a glance") {
		t.Fatal("promoted document must render the first section")
	}
}
