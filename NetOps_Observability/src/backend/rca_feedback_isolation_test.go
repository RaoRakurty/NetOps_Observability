// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// rca_feedback_isolation_test.go — the CLAUDE.md §3a rule 5 cross-org test for
// the Project 2 P7 operator-verdict surface, plus its validation and audit
// contract. org_isolation_test.go / rca_action_items_test.go are the templates.
//
// Proven here:
//   - own-only list: a tenant's per-case list never carries another tenant's rows;
//   - cross-tenant GET/POST on another tenant's correlation id → 404, and the
//     call neither reads nor writes anything (existence is never revealed);
//   - ?as_tenant= into another org is IGNORED for a non-owner, on both the
//     per-case route and the summary;
//   - the summary never mixes tenants, and its arithmetic is the metric's
//     definition (wrong / (correct+wrong+partial));
//   - validation: unknown verdict / over-long reason / contradictory wrong_part
//     answer 400, and a tenant in the BODY is ignored (owner comes from the token
//     via the object, §3a rule 2);
//   - a platform admin's write is keyed by the OBJECT's owning tenant;
//   - every accepted write is audited and counted.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/rcafeedback"
)

// fbFakeCH stands in for ClickHouse, emulating the corr_objects row policy: a
// scope that is neither the owner nor __all__ sees NO rows, which is exactly
// what turns a cross-tenant id into a 404 upstream.
func fbFakeCH(t *testing.T, owner string) {
	t.Helper()
	row := map[string]any{
		"tenant_id": owner, "version": "4",
		"top_hypothesis": "link_down", "verdict_tier": "suspected",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sql := string(b)
		scope := r.URL.Query().Get("tenant_scope")
		w.Header().Set("Content-Type", "application/json")
		if (scope == owner || scope == "__all__") && strings.Contains(sql, "FROM netops.corr_objects") {
			blob, err := json.Marshal(row)
			if err != nil {
				t.Errorf("marshal fake row: %v", err)
				return
			}
			_, _ = w.Write([]byte(`{"meta":[],"data":[` + string(blob) + `],"rows":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"meta":[],"data":[],"rows":0}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
}

// fbCorrID is the case under test (isUUIDToken-shaped).
const fbCorrID = "11111111-2222-4333-8444-555555555555"

// fbOtherCorrID is a second case of the SAME tenant — the summary must fold
// both, the per-case list must not.
const fbOtherCorrID = "66666666-7777-4888-8999-aaaaaaaaaaaa"

func feedbackServer(t *testing.T) *server {
	t.Helper()
	s := corrTestServer(t)
	s.rcaFeedback = rcafeedback.NewFileStore("") // in-memory
	s.rcaFeedbackMetrics = rcafeedback.NewMetrics()
	au, err := newAuditStore(t.TempDir() + "/audit.json")
	if err != nil {
		t.Fatalf("auditStore: %v", err)
	}
	s.audit = au
	return s
}

// post records a verdict and returns the recorder.
func fbPost(t *testing.T, s *server, id, body string, claims jwtClaims) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleCorrelationFeedback(w, req(http.MethodPost, "/api/correlations/"+id+"/feedback", body, claims), id)
	return w
}

func fbGet(t *testing.T, s *server, id string, claims jwtClaims) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleCorrelationFeedback(w, req(http.MethodGet, "/api/correlations/"+id+"/feedback", "", claims), id)
	return w
}

// seed writes one row straight into the store under `tenant` (bypassing HTTP)
// so cross-tenant reads have something they must NOT see.
func fbSeed(t *testing.T, s *server, tenant, corrID, verdict, template string, at time.Time) rcafeedback.Feedback {
	t.Helper()
	f, err := s.rcaFeedback.Add(t.Context(), tenant, false, rcafeedback.Feedback{
		TenantID: tenant, CorrelationID: corrID, Verdict: verdict,
		TopHypothesis: template, CreatedBy: "seed@" + tenant, CreatedAt: at,
	})
	if err != nil {
		t.Fatalf("seed %s/%s: %v", tenant, verdict, err)
	}
	return f
}

// ---- happy path + server-owned fields -----------------------------------------

func TestRcaFeedbackCreateStampsServerOwnedFields(t *testing.T) {
	fbFakeCH(t, "acme")
	s := feedbackServer(t)

	// A tenant_id AND an id in the body must be IGNORED, not honoured.
	w := fbPost(t, s, fbCorrID, `{"verdict":"wrong","wrong_part":"owner",
	    "reason":"the seam owner was the ISP, not our edge",
	    "correlation_version":3,"tenant_id":"globex","id":"attacker-chosen",
	    "created_by":"someone-else"}`, acme())
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d (%s)", w.Code, w.Body.String())
	}
	var got rcafeedback.Feedback
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.TenantID != "acme" {
		t.Fatalf("BODY TENANT HONOURED: owner = %q, want acme", got.TenantID)
	}
	if got.ID == "attacker-chosen" || got.ID == "" {
		t.Fatalf("id must be server-minted, got %q", got.ID)
	}
	if got.CreatedBy != "a@acme" {
		t.Fatalf("author must come from the token, got %q", got.CreatedBy)
	}
	if got.CorrelationID != fbCorrID || got.Verdict != "wrong" || got.WrongPart != "owner" {
		t.Fatalf("record wrong: %+v", got)
	}
	if got.CorrelationVersion == nil || *got.CorrelationVersion != 3 {
		t.Fatalf("correlation_version not captured: %+v", got.CorrelationVersion)
	}
	// Engine context is copied from the object, not the client.
	if got.TopHypothesis != "link_down" || got.VerdictTier != "suspected" {
		t.Fatalf("engine context not stamped from the object: %+v", got)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("created_at not stamped")
	}
	if n := s.rcaFeedbackMetrics.Snapshot()["wrong"]; n != 1 {
		t.Fatalf("netops_rca_feedback_total{verdict=\"wrong\"} = %d, want 1", n)
	}

	// GET reads it back, newest first.
	w = fbGet(t, s, fbCorrID, acme())
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d (%s)", w.Code, w.Body.String())
	}
	var list struct {
		CorrelationID string                 `json:"correlation_id"`
		Feedback      []rcafeedback.Feedback `json:"feedback"`
		Count         int                    `json:"count"`
	}
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if list.Count != 1 || len(list.Feedback) != 1 || list.Feedback[0].ID != got.ID {
		t.Fatalf("list wrong: %+v", list)
	}
}

func TestRcaFeedbackWriteIsAudited(t *testing.T) {
	fbFakeCH(t, "acme")
	s := feedbackServer(t)
	if w := fbPost(t, s, fbCorrID, `{"verdict":"wrong","wrong_part":"cause","reason":"secret operator prose"}`, acme()); w.Code != http.StatusCreated {
		t.Fatalf("create = %d (%s)", w.Code, w.Body.String())
	}
	events, err := s.audit.List("acme", false, auditQuery{Limit: 50})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	var hit *AuditEvent
	for i := range events {
		if events[i].Detail != nil && events[i].Detail["action"] == "rca_feedback_create" {
			hit = &events[i]
			break
		}
	}
	if hit == nil {
		t.Fatalf("no audit entry for the verdict write: %+v", events)
	}
	if hit.Actor != "a@acme" || hit.Tenant != "acme" || hit.Decision != "allow" {
		t.Fatalf("audit entry wrong: %+v", *hit)
	}
	if hit.Detail["correlation_id"] != fbCorrID || hit.Detail["verdict"] != "wrong" || hit.Detail["wrong_part"] != "cause" {
		t.Fatalf("audit detail wrong: %+v", hit.Detail)
	}
	// §8: the free-text reason is operator prose and is NOT copied into the trail.
	blob, err := json.Marshal(hit.Detail)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "secret operator prose") {
		t.Fatalf("audit detail leaked the reason text: %s", blob)
	}
}

// ---- validation ---------------------------------------------------------------

func TestRcaFeedbackValidation(t *testing.T) {
	fbFakeCH(t, "acme")
	s := feedbackServer(t)
	for _, c := range []struct{ name, body string }{
		{"empty body", `{}`},
		{"unknown verdict", `{"verdict":"maybe"}`},
		{"unknown wrong_part", `{"verdict":"wrong","wrong_part":"vibes"}`},
		{"wrong_part on correct", `{"verdict":"correct","wrong_part":"cause"}`},
		{"reason too long", `{"verdict":"wrong","reason":"` + strings.Repeat("x", 501) + `"}`},
		{"version ahead of the object", `{"verdict":"wrong","correlation_version":99}`},
		{"version zero", `{"verdict":"wrong","correlation_version":0}`},
		{"malformed json", `{"verdict":`},
	} {
		w := fbPost(t, s, fbCorrID, c.body, acme())
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: = %d, want 400 (%s)", c.name, w.Code, w.Body.String())
		}
	}
	// Nothing was stored by any refused write.
	if w := fbGet(t, s, fbCorrID, acme()); !strings.Contains(w.Body.String(), `"count":0`) {
		t.Fatalf("a refused write was stored: %s", w.Body.String())
	}
}

func TestRcaFeedbackRejectsUnknownQueryAndMethod(t *testing.T) {
	fbFakeCH(t, "acme")
	s := feedbackServer(t)
	w := httptest.NewRecorder()
	s.handleCorrelationFeedback(w, req(http.MethodGet, "/api/correlations/"+fbCorrID+"/feedback?page_size=1", "", acme()), fbCorrID)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown query param = %d, want 400", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleCorrelationFeedback(w, req(http.MethodDelete, "/api/correlations/"+fbCorrID+"/feedback", "", acme()), fbCorrID)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE = %d, want 405", w.Code)
	}
}

// TestRcaFeedbackWriteNeedsIncidentActionPermission pins the permission split:
// reading a case's verdicts is the correlations READ permission; recording one
// is the incident-action WRITE permission (alerts:write) the ack/assign actions
// use. A read-only principal may look, never judge.
func TestRcaFeedbackWriteNeedsIncidentActionPermission(t *testing.T) {
	fbFakeCH(t, "acme")
	s := feedbackServer(t)
	ro := jwtClaims{Sub: "ro@acme", Role: RoleReadOnly, Tenant: "acme"}
	if w := fbPost(t, s, fbCorrID, `{"verdict":"correct"}`, ro); w.Code != http.StatusForbidden {
		t.Fatalf("read-only POST = %d, want 403 (%s)", w.Code, w.Body.String())
	}
	if w := fbGet(t, s, fbCorrID, ro); w.Code != http.StatusOK {
		t.Fatalf("read-only GET = %d, want 200 (%s)", w.Code, w.Body.String())
	}
}

// ---- §3a cross-org isolation ---------------------------------------------------

func TestRcaFeedbackCrossTenantIs404(t *testing.T) {
	fbFakeCH(t, "acme") // the case belongs to acme
	s := feedbackServer(t)
	seeded := fbSeed(t, s, "acme", fbCorrID, "wrong", "link_down", time.Now().UTC())

	// Every method from a foreign tenant answers 404 — never 403, never an
	// empty 200: the id's existence is not revealed either way.
	if w := fbGet(t, s, fbCorrID, globex()); w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant GET = %d, want 404 (%s)", w.Code, w.Body.String())
	}
	if w := fbPost(t, s, fbCorrID, `{"verdict":"correct"}`, globex()); w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant POST = %d, want 404 (%s)", w.Code, w.Body.String())
	}

	// The owner's register is untouched and no foreign row was created.
	own, err := s.rcaFeedback.List(t.Context(), "acme", false, fbCorrID)
	if err != nil {
		t.Fatal(err)
	}
	if len(own) != 1 || own[0].ID != seeded.ID {
		t.Fatalf("a cross-tenant call mutated the owner's register: %+v", own)
	}
	foreign, err := s.rcaFeedback.List(t.Context(), "globex", false, fbCorrID)
	if err != nil {
		t.Fatal(err)
	}
	if len(foreign) != 0 {
		t.Fatalf("a cross-tenant call created foreign rows: %+v", foreign)
	}
}

// TestRcaFeedbackListIsOwnTenantOnly proves the per-case list filters in the
// STORE, not merely at the ClickHouse pre-read: two tenants holding verdicts on
// the SAME case id must each see only their own.
func TestRcaFeedbackListIsOwnTenantOnly(t *testing.T) {
	fbFakeCH(t, "acme")
	s := feedbackServer(t)
	now := time.Now().UTC()
	mine := fbSeed(t, s, "acme", fbCorrID, "wrong", "link_down", now)
	theirs := fbSeed(t, s, "globex", fbCorrID, "correct", "bgp_flap", now)

	w := fbGet(t, s, fbCorrID, acme())
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, mine.ID) {
		t.Fatalf("own row missing: %s", body)
	}
	if strings.Contains(body, theirs.ID) || strings.Contains(body, "globex") {
		t.Fatalf("TENANT LEAK: acme's list carried globex's verdict: %s", body)
	}
}

// TestRcaFeedbackAsTenantIgnoredForNonOwner — §3a rule 5's third clause. A
// tenant user who sets ?as_tenant= (or whose token carries an acting tenant)
// stays confined to its own tenant on BOTH routes.
func TestRcaFeedbackAsTenantIgnoredForNonOwner(t *testing.T) {
	fbFakeCH(t, "acme")
	s := feedbackServer(t)
	now := time.Now().UTC()
	mine := fbSeed(t, s, "acme", fbCorrID, "wrong", "link_down", now)
	theirs := fbSeed(t, s, "globex", fbCorrID, "correct", "bgp_flap", now)

	// principalTenant NEVER trusts ActingTenant for a non-owner (tenancy.go).
	spoofed := acme()
	spoofed.ActingTenant = "globex"

	w := httptest.NewRecorder()
	s.handleCorrelationFeedback(w, req(http.MethodGet,
		"/api/correlations/"+fbCorrID+"/feedback?as_tenant=globex", "", spoofed), fbCorrID)
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d (%s)", w.Code, w.Body.String())
	}
	if body := w.Body.String(); strings.Contains(body, theirs.ID) || !strings.Contains(body, mine.ID) {
		t.Fatalf("as_tenant was honoured for a non-owner: %s", body)
	}

	w = httptest.NewRecorder()
	s.handleRcaFeedbackSummary(w, req(http.MethodGet, "/api/correlations/feedback/summary?as_tenant=globex", "", spoofed))
	if w.Code != http.StatusOK {
		t.Fatalf("summary = %d (%s)", w.Code, w.Body.String())
	}
	var sum fbSummary
	if err := json.NewDecoder(w.Body).Decode(&sum); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if sum.N != 1 || sum.Counts["wrong"] != 1 || sum.Counts["correct"] != 0 {
		t.Fatalf("as_tenant leaked another org into the summary: %+v", sum)
	}
}

// TestRcaFeedbackPlatformAdminKeysByObjectTenant — a cross-tenant caller writes
// against acme's case; the row is owned by acme, never by the admin.
func TestRcaFeedbackPlatformAdminKeysByObjectTenant(t *testing.T) {
	fbFakeCH(t, "acme")
	s := feedbackServer(t)
	w := fbPost(t, s, fbCorrID, `{"verdict":"partial","wrong_part":"evidence"}`, superA())
	if w.Code != http.StatusCreated {
		t.Fatalf("platform-admin create = %d (%s)", w.Code, w.Body.String())
	}
	own, err := s.rcaFeedback.List(t.Context(), "acme", false, fbCorrID)
	if err != nil {
		t.Fatal(err)
	}
	if len(own) != 1 || own[0].TenantID != "acme" || own[0].CreatedBy != "root" {
		t.Fatalf("row must key by the OBJECT's owning tenant: %+v", own)
	}
}

// ---- summary -------------------------------------------------------------------

type fbSummary struct {
	Days              int            `json:"days"`
	N                 int            `json:"n"`
	Counts            map[string]int `json:"counts"`
	FalsePositiveRate *float64       `json:"false_positive_rate"`
	ByTemplate        []struct {
		Template          string   `json:"template"`
		N                 int      `json:"n"`
		FalsePositiveRate *float64 `json:"false_positive_rate"`
	} `json:"by_template"`
}

func fbSummaryFor(t *testing.T, s *server, query string, claims jwtClaims) (int, fbSummary) {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleRcaFeedbackSummary(w, req(http.MethodGet, "/api/correlations/feedback/summary"+query, "", claims))
	var out fbSummary
	if w.Code == http.StatusOK {
		if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
			t.Fatalf("decode summary: %v", err)
		}
	}
	return w.Code, out
}

func TestRcaFeedbackSummaryArithmeticAndTenantScope(t *testing.T) {
	s := feedbackServer(t)
	now := time.Now().UTC()
	// acme: 2 correct, 1 wrong, 1 partial across two cases and two templates.
	fbSeed(t, s, "acme", fbCorrID, "correct", "link_down", now)
	fbSeed(t, s, "acme", fbCorrID, "wrong", "link_down", now)
	fbSeed(t, s, "acme", fbOtherCorrID, "correct", "bgp_flap", now)
	fbSeed(t, s, "acme", fbOtherCorrID, "partial", "bgp_flap", now)
	// globex must never appear in acme's numbers.
	for i := 0; i < 5; i++ {
		fbSeed(t, s, "globex", fbCorrID, "wrong", "link_down", now)
	}

	code, sum := fbSummaryFor(t, s, "?days=30", acme())
	if code != http.StatusOK {
		t.Fatalf("summary = %d", code)
	}
	if sum.Days != 30 || sum.N != 4 {
		t.Fatalf("summary n/days wrong: %+v", sum)
	}
	if sum.Counts["correct"] != 2 || sum.Counts["wrong"] != 1 || sum.Counts["partial"] != 1 {
		t.Fatalf("SUMMARY MIXED TENANTS or miscounted: %+v", sum.Counts)
	}
	if sum.FalsePositiveRate == nil || *sum.FalsePositiveRate != 0.25 {
		t.Fatalf("false_positive_rate must be wrong/(correct+wrong+partial) = 0.25, got %v", sum.FalsePositiveRate)
	}
	if len(sum.ByTemplate) != 2 {
		t.Fatalf("want a per-template breakdown of 2, got %+v", sum.ByTemplate)
	}
	for _, b := range sum.ByTemplate {
		switch b.Template {
		case "link_down":
			if b.N != 2 || *b.FalsePositiveRate != 0.5 {
				t.Fatalf("link_down breakdown wrong: %+v", b)
			}
		case "bgp_flap":
			if b.N != 2 || *b.FalsePositiveRate != 0 {
				t.Fatalf("bgp_flap breakdown wrong: %+v", b)
			}
		default:
			t.Fatalf("unexpected template %q (cross-tenant template leak?)", b.Template)
		}
	}

	// globex sees only its own five.
	_, other := fbSummaryFor(t, s, "?days=30", globex())
	if other.N != 5 || other.Counts["wrong"] != 5 || *other.FalsePositiveRate != 1 {
		t.Fatalf("globex summary mixed tenants: %+v", other)
	}

	// A tenant with no verdicts gets an honest NULL rate, never 0.
	_, none := fbSummaryFor(t, s, "?days=30", jwtClaims{Sub: "u@initech", Role: RoleOperator, Tenant: "initech"})
	if none.N != 0 || none.FalsePositiveRate != nil {
		t.Fatalf("an empty sample must report no rate: %+v", none)
	}
}

func TestRcaFeedbackSummaryWindowAndBadDays(t *testing.T) {
	s := feedbackServer(t)
	now := time.Now().UTC()
	fbSeed(t, s, "acme", fbCorrID, "wrong", "link_down", now)
	fbSeed(t, s, "acme", fbCorrID, "correct", "link_down", now.AddDate(0, 0, -40))

	_, week := fbSummaryFor(t, s, "?days=7", acme())
	if week.N != 1 || week.Counts["wrong"] != 1 {
		t.Fatalf("the 7-day window must exclude the 40-day-old row: %+v", week)
	}
	_, year := fbSummaryFor(t, s, "?days=365", acme())
	if year.N != 2 {
		t.Fatalf("the 365-day window must include both: %+v", year)
	}

	// Fail-closed parameter handling (F-57/F-74): a bad or out-of-range `days`
	// answers 400 rather than silently becoming the default.
	for _, q := range []string{"?days=abc", "?days=0", "?days=366", "?days=-1", "?window=7"} {
		if code, _ := fbSummaryFor(t, s, q, acme()); code != http.StatusBadRequest {
			t.Errorf("summary %s = %d, want 400", q, code)
		}
	}
}

func TestRcaFeedbackSummaryPlatformOwnerSeesAcrossTenants(t *testing.T) {
	s := feedbackServer(t)
	now := time.Now().UTC()
	fbSeed(t, s, "acme", fbCorrID, "wrong", "link_down", now)
	fbSeed(t, s, "globex", fbCorrID, "correct", "link_down", now)

	_, all := fbSummaryFor(t, s, "?days=30", superA())
	if all.N != 2 || all.Counts["wrong"] != 1 || all.Counts["correct"] != 1 {
		t.Fatalf("the platform owner's aggregate must span tenants: %+v", all)
	}
	// Narrowed with an acting tenant, the owner sees exactly that tenant.
	owner := superA()
	owner.ActingTenant = "globex"
	_, one := fbSummaryFor(t, s, "?days=30", owner)
	if one.N != 1 || one.Counts["correct"] != 1 {
		t.Fatalf("as_tenant narrowing failed for the platform owner: %+v", one)
	}
}

func TestRcaFeedbackStoreUnavailableIs503(t *testing.T) {
	fbFakeCH(t, "acme")
	s := corrTestServer(t) // no store wired
	if w := fbGet(t, s, fbCorrID, acme()); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing store = %d, want 503", w.Code)
	}
	w := httptest.NewRecorder()
	s.handleRcaFeedbackSummary(w, req(http.MethodGet, "/api/correlations/feedback/summary", "", acme()))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing store (summary) = %d, want 503", w.Code)
	}
}
