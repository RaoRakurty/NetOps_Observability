// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_eval_consent_test.go — tracker 337 N-H3, consented pooling of eval
// candidates. CLAUDE.md §3a rule 5 for /api/ai/eval-consent and for the pooled
// /api/ai/triage/candidates export:
//   - consent is opt-in and defaults off; a person reads and sets only their
//     own; an API key, the unauthenticated and the platform view are refused;
//     a body naming anyone is refused; grant and revoke are audited;
//   - a consenting colleague's question joins THEIR OWN workspace's export,
//     marked pooled; a non-consenting colleague's never does; another tenant's
//     consenting user never does; revoking removes them from the next export;
//   - the platform owner's export carries no pooled text; as_tenant is ignored.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/aientitlement"
	"netops/backend/internal/evalconsent"
	"netops/backend/internal/iristriage"
)

// selfPlaneProbes lists every selfPlane AI route; TestEveryAIRouteIsEntitlementGated
// requires each one here and TestSelfPlaneRoutesAdmitAnyPersonWithoutEntitlements
// probes them.
var selfPlaneProbes = []string{"/api/ai/eval-consent"}

func consentCall(t *testing.T, s *server, c *jwtClaims, method, path, body string) (int, string) {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if c != nil {
		r = r.WithContext(context.WithValue(r.Context(), userCtxKey, *c))
	}
	w := httptest.NewRecorder()
	s.handleAIEvalConsent(w, r)
	return w.Code, w.Body.String()
}

func candidatesOf(t *testing.T, s *server, c jwtClaims, path string) iristriage.CandidateFile {
	t.Helper()
	code, body := triageCall(t, s, c, path)
	if code != http.StatusOK {
		t.Fatalf("candidates: %d %s", code, body)
	}
	var f iristriage.CandidateFile
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func pooledQuestions(f iristriage.CandidateFile) (own, pooled []string) {
	for _, c := range f.Candidates {
		if c.Pooled {
			pooled = append(pooled, c.Question)
		} else {
			own = append(own, c.Question)
		}
	}
	return own, pooled
}

func TestEvalConsentIsOptInAndEachPersonsOwn(t *testing.T) {
	s, a, _ := ledgerFixture(t)
	s.evalConsent = evalconsent.NewMemStore()
	carol := a
	carol.Sub, carol.Role = "carol", "operator"

	code, body := consentCall(t, s, &carol, http.MethodGet, "/api/ai/eval-consent", "")
	if code != http.StatusOK || !strings.Contains(body, `"consented":false`) {
		t.Fatalf("default must be off: %d %s", code, body)
	}
	if code, body = consentCall(t, s, &carol, http.MethodPut, "/api/ai/eval-consent", `{"consented":true}`); code != http.StatusOK || !strings.Contains(body, `"consented":true`) {
		t.Fatalf("grant: %d %s", code, body)
	}
	// Someone else's choice is untouched by carol's.
	if _, body = consentCall(t, s, &a, http.MethodGet, "/api/ai/eval-consent", ""); !strings.Contains(body, `"consented":false`) {
		t.Fatalf("carol's grant changed another person's choice: %s", body)
	}
	if code, body = consentCall(t, s, &carol, http.MethodPut, "/api/ai/eval-consent", `{"consented":false}`); code != http.StatusOK || !strings.Contains(body, `"consented":false`) {
		t.Fatalf("revoke: %d %s", code, body)
	}
	// Both changes are in the audit log, under carol, in her tenant.
	evs, err := s.audit.List(a.Tenant, false, auditQuery{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range evs {
		if act, _ := e.Detail["action"].(string); strings.HasPrefix(act, "ai.eval_consent.") && e.Actor == "carol" {
			seen[act] = true
		}
	}
	if !seen["ai.eval_consent.grant"] || !seen["ai.eval_consent.revoke"] {
		t.Fatalf("grant and revoke must both be audited: %v", seen)
	}
}

func TestEvalConsentRefusals(t *testing.T) {
	s, a, _ := ledgerFixture(t)
	s.evalConsent = evalconsent.NewMemStore()
	if code, _ := consentCall(t, s, nil, http.MethodGet, "/api/ai/eval-consent", ""); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", code)
	}
	key := a
	key.Sub = "apikey:k1"
	if code, _ := consentCall(t, s, &key, http.MethodPut, "/api/ai/eval-consent", `{"consented":true}`); code != http.StatusForbidden {
		t.Fatalf("an API key made a person's choice: %d", code)
	}
	owner := jwtClaims{Sub: "root", Role: "admin", Tenant: TenantGlobal}
	if code, _ := consentCall(t, s, &owner, http.MethodPut, "/api/ai/eval-consent", `{"consented":true}`); code != http.StatusBadRequest {
		t.Fatalf("the platform view has no workspace to share with: %d", code)
	}
	for _, body := range []string{`{"consented":true,"principal":"bob"}`, `{"consented":true,"tenant":"t-b"}`, `{}`, `not json`} {
		if code, _ := consentCall(t, s, &a, http.MethodPut, "/api/ai/eval-consent", body); code != http.StatusBadRequest {
			t.Fatalf("body %s: %d — want 400", body, code)
		}
	}
	if code, _ := consentCall(t, s, &a, http.MethodPost, "/api/ai/eval-consent", `{"consented":true}`); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", code)
	}
	if c, _ := s.evalConsent.Get(context.Background(), a.Tenant, "bob"); c.Consented {
		t.Fatal("a refused body still set someone's consent")
	}
	s.evalConsent = nil
	if code, _ := consentCall(t, s, &a, http.MethodGet, "/api/ai/eval-consent", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("no store: %d", code)
	}
}

func TestPooledCandidatesAreConsentingColleaguesOfTheSameWorkspace(t *testing.T) {
	s, a, b := ledgerFixture(t)
	s.evalConsent = evalconsent.NewMemStore()
	seedMiss(t, s, a.Tenant, a.Sub, "where do I set the polling interval", iristriage.NoData)
	seedMiss(t, s, a.Tenant, "carol", "why is the dallas box slow at night", iristriage.NoTool)
	seedMiss(t, s, a.Tenant, "dave", "dave private wording never shared", iristriage.Wording)
	seedMiss(t, s, b.Tenant, "eve", "globex consenting question", iristriage.NoTool)
	ctx := context.Background()
	for _, p := range []struct{ tenant, who string }{{a.Tenant, "carol"}, {b.Tenant, "eve"}} {
		if _, err := s.evalConsent.Set(ctx, p.tenant, p.who, true, time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	f := candidatesOf(t, s, a, "/api/ai/triage/candidates")
	own, pooled := pooledQuestions(f)
	if len(own) != 1 || own[0] != "where do I set the polling interval" {
		t.Fatalf("own candidates %v", own)
	}
	if len(pooled) != 1 || pooled[0] != "why is the dallas box slow at night" {
		t.Fatalf("pooled candidates %v — want exactly carol's", pooled)
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"dave private wording", "globex", "carol", "eve"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("export leaks %q: %s", leak, raw)
		}
	}
	// The triage view still withholds the consenting colleague's text: consent
	// covers the export for evaluation, not the admin's dashboard.
	if _, view := triageCall(t, s, a, "/api/ai/triage"); strings.Contains(string(view), "dallas box") {
		t.Fatalf("triage view shows a colleague's text: %s", view)
	}
	// as_tenant never moves the export into t-b.
	walked := candidatesOf(t, s, a, "/api/ai/triage/candidates?as_tenant="+b.Tenant)
	if raw, _ := json.Marshal(walked); strings.Contains(string(raw), "globex") {
		t.Fatalf("as_tenant walked the pooled export into t-b: %s", raw)
	}

	// Revoking takes effect at the next export.
	if _, err := s.evalConsent.Set(ctx, a.Tenant, "carol", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, pooled = pooledQuestions(candidatesOf(t, s, a, "/api/ai/triage/candidates")); len(pooled) != 0 {
		t.Fatalf("revoked consent still pooled: %v", pooled)
	}
}

func TestPlatformOwnerExportCarriesNoPooledText(t *testing.T) {
	s, _, _ := ledgerFixture(t)
	s.evalConsent = evalconsent.NewMemStore()
	ta, err := s.tenants.Create("Consent A", "consent-a", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	seedMiss(t, s, ta.ID, "carol", "consented but platform must not read this", iristriage.NoTool)
	if _, err := s.evalConsent.Set(context.Background(), ta.ID, "carol", true, time.Now()); err != nil {
		t.Fatal(err)
	}
	owner := jwtClaims{Sub: "root", Role: "admin", Tenant: TenantGlobal}
	f := candidatesOf(t, s, owner, "/api/ai/triage/candidates")
	if raw, _ := json.Marshal(f); strings.Contains(string(raw), "platform must not read") {
		t.Fatalf("the platform owner received pooled text: %s", raw)
	}
}

func TestSelfPlaneRoutesAdmitAnyPersonWithoutEntitlements(t *testing.T) {
	s, h, a, _ := aiEntFixture(t)
	s.evalConsent = evalconsent.NewMemStore()
	s.aiEntitlementPolicy = policyWithout(t, s, aientitlement.All()...)
	op := a
	op.Role = "operator"
	for _, route := range selfPlaneProbes {
		if w := serveAs(h, op, http.MethodGet, route, ""); w.Code != http.StatusOK {
			t.Errorf("%s as an operator with every AI entitlement withheld: %d %s — a person must always reach their own setting", route, w.Code, w.Body.String())
		}
		key := op
		key.Sub = "apikey:probe"
		if w := serveAs(h, key, http.MethodGet, route, ""); w.Code != http.StatusForbidden {
			t.Errorf("%s as an API key: %d — want 403", route, w.Code)
		}
	}
}
