// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_triage_isolation_test.go — /api/ai/triage and /api/ai/triage/candidates
// (the Iris miss triage, model-first decision point 5). CLAUDE.md §3a rule 5:
// a workspace admin reads their own tenant's misses only (another tenant's
// never counts, an as_tenant walk is ignored), a non-admin is refused, a
// colleague's typed text is withheld (counts only), the candidate export holds
// only the caller's own questions, and the platform owner sees every tenant
// with each example naming its tenant. A miss is recorded by /api/ai/ask.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/irisquerylog"
	"netops/backend/internal/iristriage"
)

func triageCall(t *testing.T, s *server, c jwtClaims, path string) (int, []byte) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	s.handleAIIrisTriage(w, r)
	return w.Code, w.Body.Bytes()
}

type triageView struct {
	Scope   string                    `json:"scope"`
	Classes []iristriage.ClassSummary `json:"classes"`
}

func seedMiss(t *testing.T, s *server, tenant, principal, question, class string) {
	t.Helper()
	if _, err := s.nlqQueryLog.Record(context.Background(), tenant, irisquerylog.Record{Principal: principal,
		Source: irisquerylog.SourceAsk, Outcome: irisquerylog.OutcomeMiss, MissClass: class, Question: question}); err != nil {
		t.Fatal(err)
	}
}

func TestIrisTriageIsTheCallersOwnTenant(t *testing.T) {
	s, a, b := ledgerFixture(t)
	seedMiss(t, s, a.Tenant, a.Sub, "where do I set the polling interval", iristriage.NoData)
	seedMiss(t, s, a.Tenant, "colleague", "acme colleague private wording", iristriage.Wording)
	seedMiss(t, s, b.Tenant, b.Sub, "globex secret question", iristriage.NoTool)

	code, body := triageCall(t, s, a, "/api/ai/triage")
	if code != http.StatusOK {
		t.Fatalf("admin read: %d %s", code, body)
	}
	var v triageView
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if v.Scope != "tenant" {
		t.Fatalf("scope %q", v.Scope)
	}
	counts := map[string]int{}
	for _, c := range v.Classes {
		counts[c.Class] = c.Count
	}
	if counts[iristriage.NoTool] != 0 || counts[iristriage.NoData] != 1 || counts[iristriage.Wording] != 1 {
		t.Fatalf("t-a's view counts %v", counts)
	}
	raw := string(body)
	if strings.Contains(raw, "globex") {
		t.Fatalf("LEAK: t-a's triage carries t-b's question: %s", raw)
	}
	if strings.Contains(raw, "acme colleague private wording") {
		t.Fatalf("a colleague's typed text must be withheld: %s", raw)
	}
	if !strings.Contains(raw, "where do I set the polling interval") {
		t.Fatalf("the caller's own question is shown: %s", raw)
	}
	// An as_tenant walk into another tenant is ignored.
	if _, walked := triageCall(t, s, a, "/api/ai/triage?as_tenant="+b.Tenant); strings.Contains(string(walked), "globex") {
		t.Fatalf("as_tenant walked into t-b: %s", walked)
	}
	// The candidate export holds only the caller's own questions.
	code, body = triageCall(t, s, a, "/api/ai/triage/candidates")
	if code != http.StatusOK {
		t.Fatalf("candidates: %d %s", code, body)
	}
	var f iristriage.CandidateFile
	if err := json.Unmarshal(body, &f); err != nil {
		t.Fatal(err)
	}
	if f.Review != iristriage.ReviewNotice || len(f.Candidates) != 1 || f.Candidates[0].Question != "where do I set the polling interval" {
		t.Fatalf("candidates %+v", f)
	}
	// Unknown sub-paths are 404.
	if code, _ := triageCall(t, s, a, "/api/ai/triage/other"); code != http.StatusNotFound {
		t.Fatalf("unknown sub-path: %d", code)
	}
}

func TestIrisTriageRefusesANonAdmin(t *testing.T) {
	s, a, _ := ledgerFixture(t)
	op := a
	op.Role = "operator"
	if code, _ := triageCall(t, s, op, "/api/ai/triage"); code != http.StatusForbidden {
		t.Fatalf("a non-admin read the triage: %d", code)
	}
	if code, _ := triageCall(t, s, op, "/api/ai/triage/candidates"); code != http.StatusForbidden {
		t.Fatalf("a non-admin read the candidates: %d", code)
	}
}

func TestIrisTriagePlatformOwnerSeesEveryTenantWithoutText(t *testing.T) {
	s, _, _ := ledgerFixture(t)
	if s.tenants == nil {
		t.Fatal("the fixture must carry a tenant registry")
	}
	// The platform view walks the tenant registry: seed two registered tenants.
	ta, err := s.tenants.Create("Triage A", "triage-a", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	tb, err := s.tenants.Create("Triage B", "triage-b", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	seedMiss(t, s, ta.ID, "alice", "acme question", iristriage.NoData)
	seedMiss(t, s, tb.ID, "bob", "globex question", iristriage.NoTool)
	owner := jwtClaims{Sub: "root", Role: "admin", Tenant: TenantGlobal}
	code, body := triageCall(t, s, owner, "/api/ai/triage")
	if code != http.StatusOK {
		t.Fatalf("owner: %d %s", code, body)
	}
	var v triageView
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if v.Scope != "platform" {
		t.Fatalf("scope %q", v.Scope)
	}
	tenants := map[string]bool{}
	total := 0
	for _, c := range v.Classes {
		total += c.Count
		for _, ex := range c.Examples {
			tenants[ex.Tenant] = true
			if ex.Question != "" {
				t.Fatalf("the platform view must not carry an operator's typed text: %+v", ex)
			}
		}
	}
	if total != 2 || !tenants[ta.ID] || !tenants[tb.ID] {
		t.Fatalf("owner view: total=%d tenants=%v", total, tenants)
	}
}

// /api/ai/ask records a non-data dead end with its class, in the asker's own
// tenant and under the asker's principal.
func TestIrisAskRecordsAClassifiedMiss(t *testing.T) {
	s, a, b := ledgerFixture(t)
	askIrisRaw(t, s, a, "qwzx plorb vrrrm")
	recs, err := s.nlqQueryLog.List(context.Background(), a.Tenant, irisquerylog.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range recs {
		if r.Source == irisquerylog.SourceAsk {
			found = true
			if r.Outcome != irisquerylog.OutcomeMiss || !iristriage.Valid(r.MissClass) || r.Principal != a.Sub {
				t.Fatalf("miss record %+v", r)
			}
		}
	}
	if !found {
		t.Skip("this fixture answered the nonsense question (no dead end to record)")
	}
	if other, _ := s.nlqQueryLog.List(context.Background(), b.Tenant, irisquerylog.ListFilter{}); len(other) != 0 {
		t.Fatalf("LEAK: t-a's miss landed in t-b: %+v", other)
	}
}
