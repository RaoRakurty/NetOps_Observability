package backend

// rca_reports_list_test.go — the management RCA library (#113 point 3 follow-
// up). Pins: the bounded two-phase evaluation (SQL prefilter cap + per-
// candidate promotion evaluation through the SHARED report pipeline), the
// auto/manual union + dedupe, the no-silent-caps disclosure, and the §3a
// isolation contract: tenant A never sees tenant B's confirmed objects or
// manual promotions; an empty cross view is an empty list, not a 404.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/rca"
	"strings"
	"testing"
)

// ---- prefilter shape (pure) -------------------------------------------------

func TestRcaLibraryPrefilterSQLIsBounded(t *testing.T) {
	sql := rcaLibraryPrefilterSQL(30)
	for _, must := range []string{
		"FROM netops.corr_current FINAL",
		"verdict_tier = 'confirmed'",
		"state != 'merged'",
		// duration reuses the promotion constant (owner-tuned 2m) — never drifts
		fmt.Sprintf("dateDiff('second', window_start, window_end) >= %d", int(rca.PromotionMinDuration.Seconds())),
		"window_end >= now() - INTERVAL 2592000 SECOND", // 30 days, bounded window
		"ORDER BY window_end DESC",
		fmt.Sprintf("LIMIT %d", rcaLibraryEvalCap),
	} {
		if !strings.Contains(sql, must) {
			t.Errorf("prefilter SQL missing %q:\n%s", must, sql)
		}
	}
}

// ---- fake CH: corr_current prefilter + per-object slice, scope-enforced -----

type libFakeObj struct {
	owner string
	meta  map[string]any
	sigs  []map[string]any
}

// libAutoMeta — a confirmed 20-minute case whose report auto-promotes once its
// real-user impact signals (libImpactSigs) attach.
func libAutoMeta(owner, trigger string) map[string]any {
	hyp, _ := json.Marshal(map[string]any{"ranking": map[string]any{"hypotheses": []any{map[string]any{
		"id": "sig.ent.wan-edge.bgp-peer-down", "confidence": 0.9, "confidence_label": "confirmed",
		"satisfied": []string{"app_error_rate_high"}, "missing": []string{}, "contradicted": false,
		"verdict": map[string]any{"verdict_tier": "confirmed", "owner": "isp"},
	}}}})
	return map[string]any{
		"version": "3", "tenant_id": owner, "state": "open", "merged_into": "",
		"window_start": "2026-07-12T18:10:00Z", "window_end": "2026-07-12T18:30:00Z",
		"trigger_signal": trigger,
		"verdict_tier":   "confirmed", "top_hypothesis": "sig.ent.wan-edge.bgp-peer-down", "top_confidence": "0.9",
		"evidence_missing": "[]", "hypotheses": string(hyp), "affected": "{}",
		"layer_coverage": "{}", "app_impact": "{}", "attribution": "{}",
	}
}

// libSuspectedMeta — a case that can NEVER auto-promote (suspected verdict).
func libSuspectedMeta(owner, trigger string) map[string]any {
	m := libAutoMeta(owner, trigger)
	m["verdict_tier"] = "suspected"
	return m
}

func libSig(id, ts, kind string) map[string]any {
	return map[string]any{
		"signal_id": id, "ts": ts, "ingest_ts": ts, "source": "flow", "kind": kind,
		"observer_type": "device", "observer_id": "lb-1", "collection_path": "direct",
		"modality_class": "passive_flow", "clock_quality": "",
		"entity_type": "app", "entity_id": "portal", "entity_tokens": "[]",
		"severity": "crit", "value": float64(0), "baseline": float64(0), "deviation": float64(0),
		"metric_name": "", "attrs": "{}", "onset_uncertainty_s": float64(0),
		"phase": "", "clear_ts": "", "probe_scope": "", "probe_authority": "", "classification_source": "",
	}
}

// libImpactSigs: two attached real-user impact anomalies 15 minutes apart —
// confirmed real-user impact + duration comfortably over the 2m threshold.
func libImpactSigs(trigger string) []map[string]any {
	return []map[string]any{
		libSig(trigger, "2026-07-12 18:11:00", "app_error_rate_high"),
		libSig("22222222-2222-2222-2222-222222222222", "2026-07-12 18:26:00", "app_error_rate_high"),
	}
}

// libFakeCH emulates the row-policy-scoped reads: the corr_current prefilter
// answers per scope; per-object slice reads answer only when the object is
// visible to the request's tenant_scope. Captures every scope seen.
func libFakeCH(t *testing.T, prefilter map[string][]string, objs map[string]libFakeObj) *[]string {
	t.Helper()
	var scopes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sql := string(b)
		scope := r.URL.Query().Get("tenant_scope")
		scopes = append(scopes, scope)
		w.Header().Set("Content-Type", "application/json")
		rows := func(rs []map[string]any) {
			b, _ := json.Marshal(rs)
			_, _ = w.Write([]byte(`{"meta":[],"data":` + string(b) + `,"rows":` + intToString(len(rs)) + `}`))
		}
		empty := func() { _, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`)) }
		visible := func(owner string) bool { return scope == owner || scope == "__all__" }

		switch {
		case strings.Contains(sql, "FROM netops.corr_current"):
			var out []map[string]any
			for _, id := range prefilter[scope] {
				out = append(out, map[string]any{"correlation_id": id})
			}
			rows(out)
		case strings.Contains(sql, "max(archived_version)"):
			rows([]map[string]any{{"av": "1"}})
		case strings.Contains(sql, "FROM netops.corr_signals_archive"):
			for id, o := range objs {
				if strings.Contains(sql, "archived_for = '"+id+"'") && visible(o.owner) {
					rows(o.sigs)
					return
				}
			}
			empty()
		case strings.Contains(sql, "FROM netops.corr_objects"):
			for id, o := range objs {
				if strings.Contains(sql, "correlation_id = '"+id+"'") && visible(o.owner) {
					rows([]map[string]any{o.meta})
					return
				}
			}
			empty()
		default:
			empty()
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	return &scopes
}

func libResponse(t *testing.T, w *httptest.ResponseRecorder) (reports []rcaLibraryReport, evaluated int, truncated bool) {
	t.Helper()
	var body struct {
		Reports   []rcaLibraryReport `json:"reports"`
		Evaluated int                `json:"evaluated"`
		Truncated bool               `json:"truncated"`
		WindowDay int                `json:"window_days"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body.Reports, body.Evaluated, body.Truncated
}

const (
	libAutoID      = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" // acme, auto-promotes
	libSuspectID   = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" // acme, confirmed-prefilter shape but suspected → filtered in phase (b)
	libManualID    = "cccccccc-cccc-cccc-cccc-cccccccccccc" // acme, suspected + manual promotion
	libGlobexOwnID = "dddddddd-dddd-dddd-dddd-dddddddddddd" // globex, manual promotion
)

func libObjs() map[string]libFakeObj {
	return map[string]libFakeObj{
		libAutoID:      {owner: "acme", meta: libAutoMeta("acme", "11111111-1111-1111-1111-111111111111"), sigs: libImpactSigs("11111111-1111-1111-1111-111111111111")},
		libSuspectID:   {owner: "acme", meta: libSuspectedMeta("acme", "11111111-1111-1111-1111-111111111111"), sigs: libImpactSigs("11111111-1111-1111-1111-111111111111")},
		libManualID:    {owner: "acme", meta: libSuspectedMeta("acme", "11111111-1111-1111-1111-111111111111"), sigs: libImpactSigs("11111111-1111-1111-1111-111111111111")},
		libGlobexOwnID: {owner: "globex", meta: libSuspectedMeta("globex", "11111111-1111-1111-1111-111111111111"), sigs: libImpactSigs("11111111-1111-1111-1111-111111111111")},
	}
}

func TestRcaLibraryAutoManualUnionAndPhaseBFilter(t *testing.T) {
	libFakeCH(t, map[string][]string{"acme": {libAutoID, libSuspectID}}, libObjs())
	s := promoServer(t)
	_ = s.rcaPromotions.Set("acme", libManualID, rca.PromotionRecord{PromotedBy: "ops@acme", PromotedAt: "2026-07-18 12:00:00 UTC"})

	w := httptest.NewRecorder()
	s.handleRcaReportsLibrary(w, req(http.MethodGet, "/api/correlations/rca-reports", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", w.Code, w.Body.String())
	}
	reports, evaluated, truncated := libResponse(t, w)
	if truncated {
		t.Fatal("3 candidates must not report truncation")
	}
	if evaluated != 3 {
		t.Fatalf("evaluated = %d, want 3 (2 prefilter + 1 manual)", evaluated)
	}
	got := map[string]string{}
	for _, r := range reports {
		got[r.CorrelationID] = r.Promotion.Basis
	}
	if len(reports) != 2 {
		t.Fatalf("want auto + manual only, got %v", got)
	}
	if got[libAutoID] != "auto" {
		t.Fatalf("confirmed real outage must list with basis auto: %v", got)
	}
	if got[libManualID] != "manual" {
		t.Fatalf("manual promotion must union in with basis manual: %v", got)
	}
	if _, ok := got[libSuspectID]; ok {
		t.Fatal("phase (b) must filter a prefiltered-but-unpromoted candidate")
	}
	// Library rows are projections of the BUILT report — spot-check fields.
	for _, r := range reports {
		if r.CorrelationID == libAutoID {
			if r.Title == "" || r.DisplayID == "" || r.ReportType == "" {
				t.Fatalf("row missing display fields: %+v", r)
			}
			if r.States.Analysis != "confirmed" || r.States.Impact != "confirmed" {
				t.Fatalf("auto row states = %+v", r.States)
			}
			if r.AtAGlance.Where == "" || r.AtAGlance.What == "" {
				t.Fatalf("at_a_glance missing: %+v", r.AtAGlance)
			}
		}
	}
}

func TestRcaLibraryDedupesManualAlsoInPrefilter(t *testing.T) {
	libFakeCH(t, map[string][]string{"acme": {libAutoID}}, libObjs())
	s := promoServer(t)
	// the same id is BOTH prefiltered and manually promoted — one row, manual wins
	_ = s.rcaPromotions.Set("acme", libAutoID, rca.PromotionRecord{PromotedBy: "ops@acme", PromotedAt: "2026-07-18 12:00:00 UTC"})

	w := httptest.NewRecorder()
	s.handleRcaReportsLibrary(w, req(http.MethodGet, "/api/correlations/rca-reports", "", acme()))
	reports, evaluated, _ := libResponse(t, w)
	if evaluated != 1 || len(reports) != 1 {
		t.Fatalf("dedupe failed: evaluated=%d rows=%d", evaluated, len(reports))
	}
	if reports[0].Promotion.Basis != "manual" {
		t.Fatalf("explicit manual record must be the reported basis, got %q", reports[0].Promotion.Basis)
	}
}

func TestRcaLibraryDisclosesTruncation(t *testing.T) {
	// A full prefilter page (= the cap) must disclose truncation — no silent caps.
	ids := make([]string, rcaLibraryEvalCap)
	for i := range ids {
		ids[i] = fmt.Sprintf("%08x-0000-0000-0000-000000000000", i)
	}
	libFakeCH(t, map[string][]string{"acme": ids}, nil) // none resolvable → all skipped as 404
	s := promoServer(t)

	w := httptest.NewRecorder()
	s.handleRcaReportsLibrary(w, req(http.MethodGet, "/api/correlations/rca-reports", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	reports, evaluated, truncated := libResponse(t, w)
	if !truncated {
		t.Fatal("a full prefilter page must set truncated=true")
	}
	if evaluated != rcaLibraryEvalCap || len(reports) != 0 {
		t.Fatalf("evaluated=%d rows=%d", evaluated, len(reports))
	}
}

func TestRcaLibraryRejectsNonGet(t *testing.T) {
	libFakeCH(t, nil, nil)
	s := promoServer(t)
	w := httptest.NewRecorder()
	s.handleRcaReportsLibrary(w, req(http.MethodPost, "/api/correlations/rca-reports", "{}", acme()))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", w.Code)
	}
}

// ---- §3a isolation ----------------------------------------------------------

func TestRcaLibraryTenantIsolation(t *testing.T) {
	// acme has a confirmed auto outage + a manual promotion; globex has ONLY its
	// own manual promotion. Each caller's library is exactly its own view.
	scopes := libFakeCH(t, map[string][]string{"acme": {libAutoID}}, libObjs())
	s := promoServer(t)
	_ = s.rcaPromotions.Set("acme", libManualID, rca.PromotionRecord{PromotedBy: "ops@acme", PromotedAt: "2026-07-18 12:00:00 UTC"})
	_ = s.rcaPromotions.Set("globex", libGlobexOwnID, rca.PromotionRecord{PromotedBy: "ops@globex", PromotedAt: "2026-07-18 12:00:00 UTC"})

	// acme: its two promoted cases, nothing of globex's.
	w := httptest.NewRecorder()
	s.handleRcaReportsLibrary(w, req(http.MethodGet, "/api/correlations/rca-reports", "", acme()))
	reports, _, _ := libResponse(t, w)
	for _, r := range reports {
		if r.CorrelationID == libGlobexOwnID {
			t.Fatal("TENANT LEAK: acme listed globex's manual promotion")
		}
	}
	if len(reports) != 2 {
		t.Fatalf("acme rows = %d, want 2", len(reports))
	}

	// globex: only its own manual promotion — never acme's confirmed object,
	// never acme's manual record.
	w = httptest.NewRecorder()
	s.handleRcaReportsLibrary(w, req(http.MethodGet, "/api/correlations/rca-reports", "", globex()))
	if w.Code != http.StatusOK {
		t.Fatalf("cross view must be an empty/own list, not an error: %d", w.Code)
	}
	reports, _, _ = libResponse(t, w)
	if len(reports) != 1 || reports[0].CorrelationID != libGlobexOwnID {
		t.Fatalf("globex must see exactly its own promotion, got %+v", reports)
	}

	// a tenant with nothing promoted gets an empty list, not a 404.
	w = httptest.NewRecorder()
	s.handleRcaReportsLibrary(w, req(http.MethodGet, "/api/correlations/rca-reports", "",
		jwtClaims{Sub: "n@nobody", Role: RoleOperator, Tenant: "nobody"}))
	if w.Code != http.StatusOK {
		t.Fatalf("empty tenant = %d, want 200", w.Code)
	}
	reports, _, _ = libResponse(t, w)
	if len(reports) != 0 {
		t.Fatalf("empty tenant must list nothing, got %+v", reports)
	}

	// every ClickHouse read carried a tenant scope — none escaped unscoped.
	for _, sc := range *scopes {
		if sc == "" {
			t.Fatal("a library read reached ClickHouse without a tenant_scope")
		}
	}
}
