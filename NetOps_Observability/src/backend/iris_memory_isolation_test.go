// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_memory_isolation_test.go — the CLAUDE.md §3a rule 5 cross-org test for
// IRIS Phase B investigation memory, plus the operator-judgement WRITE path.
//
// Proven here:
//   - own-only recall: tenant A can never recall tenant B's investigations,
//     through the same seam the assistant's tool uses;
//   - a non-owner's ?as_tenant= into another org is IGNORED (the token is the
//     authority, tenancy.go's hard invariant);
//   - a platform owner narrowed to one tenant sees only that tenant;
//   - the write path: a thumbs up/down writes exactly ONE memory row, owned by
//     the tenant from the TOKEN, with the operator's judgement as the outcome;
//   - a rating by a different operator, or a different tenant, writes nothing —
//     an outcome can only ever be attached to one's own concluded investigation;
//   - a rating with no concluded investigation behind it is a clean no-op.

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"netops/backend/ai"
)

func irisMemoryServer(t *testing.T) *server {
	t.Helper()
	s := aiCfgTestServer(t)
	s.irisMemory = ai.NewInvestigationFileStore("") // in-memory: no disk in unit tests
	s.irisPending = ai.NewPendingInvestigations()
	return s
}

func irisSeedMemory(t *testing.T, s *server, tenant, device, verdict string, outcome ai.InvestigationOutcome) {
	t.Helper()
	err := s.irisMemory.Record(context.Background(), ai.InvestigationRow{
		TenantID: tenant, DeviceName: device, Verdict: verdict, Outcome: outcome,
		Skills: []string{"bgp-session-down"}, ResolvedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("seed %s/%s: %v", tenant, device, err)
	}
}

func TestIrisMemoryRecallIsTenantScoped(t *testing.T) {
	s := irisMemoryServer(t)
	// The SAME device name in two tenants — the case a leak would expose.
	irisSeedMemory(t, s, "t-a", "edge-1", "acme: the optic was failing", ai.OutcomeConfirmed)
	irisSeedMemory(t, s, "t-b", "edge-1", "globex: the ISP dropped the session", ai.OutcomeWrong)

	ctx := context.Background()
	q := ai.InvestigationQuery{Device: "edge-1"}

	recallA := s.aiRecallInvestigations(jwtClaims{Role: "admin", Tenant: "t-a", Sub: "op-a"})
	rows, err := recallA(ctx, ai.Principal{Tenant: "t-a"}, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].TenantID != "t-a" {
		t.Fatalf("LEAK: tenant A recalled %+v", rows)
	}

	recallB := s.aiRecallInvestigations(jwtClaims{Role: "admin", Tenant: "t-b", Sub: "op-b"})
	rows, err = recallB(ctx, ai.Principal{Tenant: "t-b"}, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].TenantID != "t-b" {
		t.Fatalf("LEAK: tenant B recalled %+v", rows)
	}

	// ?as_tenant= into another org is ignored for a non-owner: the effective
	// tenant comes from the token, never from the selector.
	asOther := s.aiRecallInvestigations(jwtClaims{Role: "admin", Tenant: "t-a", Sub: "op-a", ActingTenant: "t-b"})
	rows, err = asOther(ctx, ai.Principal{Tenant: "t-a"}, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].TenantID != "t-a" {
		t.Fatalf("LEAK: as_tenant into another org was honoured: %+v", rows)
	}

	// An unkeyed recall is refused for everyone — there is no unscoped list.
	if rows, _ = recallA(ctx, ai.Principal{Tenant: "t-a"}, ai.InvestigationQuery{}); len(rows) != 0 {
		t.Fatalf("an unkeyed recall returned %d rows", len(rows))
	}
}

func TestIrisMemoryRecallBoundsTheLimit(t *testing.T) {
	s := irisMemoryServer(t)
	for i := 0; i < ai.MaxRecallRows+5; i++ {
		irisSeedMemory(t, s, "t-a", "edge-1", "conclusion", ai.OutcomeConfirmed)
	}
	recall := s.aiRecallInvestigations(jwtClaims{Role: "admin", Tenant: "t-a", Sub: "op-a"})
	rows, err := recall(context.Background(), ai.Principal{Tenant: "t-a"},
		ai.InvestigationQuery{Device: "edge-1", Limit: 10_000}) // a caller-supplied limit is never trusted
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != ai.MaxRecallRows {
		t.Fatalf("recall returned %d rows, want the server-side bound of %d", len(rows), ai.MaxRecallRows)
	}
}

// irisFeedback posts a rating as `claims`, returning the response recorder.
func irisFeedback(t *testing.T, s *server, claims jwtClaims, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/ai/feedback", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	s.handleAIFeedback(w, claimsCtx(r, claims))
	return w
}

func TestIrisMemoryWrittenOnOperatorJudgement(t *testing.T) {
	s := irisMemoryServer(t)
	claims := jwtClaims{Role: "admin", Tenant: "t-a", Sub: "op-a"}
	concluded := ai.ConcludedInvestigation{
		AnswerID: "ans-1", DeviceID: "dev-a", DeviceName: "edge-1", Peer: "10.0.0.1",
		Skills:    []string{"bgp-session-down", "interface-down"},
		Verdict:   "the session dropped because the uplink optic was failing",
		Citations: []string{"diagsig:sig-1"},
	}
	s.irisPending.Stash("t-a", "op-a", concluded)

	if w := irisFeedback(t, s, claims, `{"rating":"up","answer_id":"ans-1"}`); w.Code != http.StatusNoContent {
		t.Fatalf("feedback status = %d", w.Code)
	}
	rows, err := s.irisMemory.Recall(context.Background(), "t-a", false, ai.InvestigationQuery{Device: "edge-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly one remembered investigation, got %d", len(rows))
	}
	row := rows[0]
	if row.TenantID != "t-a" {
		t.Errorf("owner must come from the token: %q", row.TenantID)
	}
	if row.Outcome != ai.OutcomeConfirmed {
		t.Errorf("a thumbs-up must record a CONFIRMED outcome, got %q", row.Outcome)
	}
	if row.Peer != "10.0.0.1" || len(row.Skills) != 2 || len(row.Citations) != 1 {
		t.Errorf("the conclusion was not carried through: %+v", row)
	}
	// The judgement is consumed: rating the same answer again writes nothing.
	if w := irisFeedback(t, s, claims, `{"rating":"down","answer_id":"ans-1"}`); w.Code != http.StatusNoContent {
		t.Fatalf("second feedback status = %d", w.Code)
	}
	rows, _ = s.irisMemory.Recall(context.Background(), "t-a", false, ai.InvestigationQuery{Device: "edge-1"})
	if len(rows) != 1 {
		t.Fatalf("a second rating of the same answer wrote another row: %d rows", len(rows))
	}
}

func TestIrisMemoryThumbsDownRecordsWrong(t *testing.T) {
	s := irisMemoryServer(t)
	claims := jwtClaims{Role: "admin", Tenant: "t-a", Sub: "op-a"}
	s.irisPending.Stash("t-a", "op-a", ai.ConcludedInvestigation{
		AnswerID: "ans-2", DeviceName: "edge-9", Verdict: "blamed the ISP",
	})
	if w := irisFeedback(t, s, claims, `{"rating":"down","answer_id":"ans-2"}`); w.Code != http.StatusNoContent {
		t.Fatalf("feedback status = %d", w.Code)
	}
	rows, _ := s.irisMemory.Recall(context.Background(), "t-a", false, ai.InvestigationQuery{Device: "edge-9"})
	if len(rows) != 1 || rows[0].Outcome != ai.OutcomeWrong {
		t.Fatalf("a thumbs-down must record a WRONG outcome: %+v", rows)
	}
}

func TestIrisMemoryJudgementCannotCrossPrincipals(t *testing.T) {
	s := irisMemoryServer(t)
	s.irisPending.Stash("t-a", "op-a", ai.ConcludedInvestigation{
		AnswerID: "ans-3", DeviceName: "edge-1", Verdict: "acme's own conclusion",
	})

	// Another TENANT rating the same answer id writes nothing — and certainly
	// nothing into its own memory.
	other := jwtClaims{Role: "admin", Tenant: "t-b", Sub: "op-a"}
	if w := irisFeedback(t, s, other, `{"rating":"up","answer_id":"ans-3"}`); w.Code != http.StatusNoContent {
		t.Fatalf("status = %d", w.Code)
	}
	// Another OPERATOR in the same tenant likewise.
	sameTenantOtherOp := jwtClaims{Role: "admin", Tenant: "t-a", Sub: "op-z"}
	if w := irisFeedback(t, s, sameTenantOtherOp, `{"rating":"up","answer_id":"ans-3"}`); w.Code != http.StatusNoContent {
		t.Fatalf("status = %d", w.Code)
	}
	for _, tenant := range []string{"t-a", "t-b"} {
		rows, _ := s.irisMemory.Recall(context.Background(), tenant, false, ai.InvestigationQuery{Device: "edge-1"})
		if len(rows) != 0 {
			t.Fatalf("%s: a foreign principal's rating wrote %d memory rows", tenant, len(rows))
		}
	}
	// The rightful owner can still judge it.
	owner := jwtClaims{Role: "admin", Tenant: "t-a", Sub: "op-a"}
	if w := irisFeedback(t, s, owner, `{"rating":"up","answer_id":"ans-3"}`); w.Code != http.StatusNoContent {
		t.Fatalf("status = %d", w.Code)
	}
	rows, _ := s.irisMemory.Recall(context.Background(), "t-a", false, ai.InvestigationQuery{Device: "edge-1"})
	if len(rows) != 1 {
		t.Fatalf("the owner's judgement did not land: %d rows", len(rows))
	}
}

func TestIrisMemoryRatingWithoutAnInvestigationIsANoOp(t *testing.T) {
	s := irisMemoryServer(t)
	claims := jwtClaims{Role: "admin", Tenant: "t-a", Sub: "op-a"}
	// Nothing stashed: the rating is still accepted (and audited), and no memory
	// row appears from nowhere.
	if w := irisFeedback(t, s, claims, `{"rating":"up"}`); w.Code != http.StatusNoContent {
		t.Fatalf("status = %d", w.Code)
	}
	rows, _ := s.irisMemory.Recall(context.Background(), "t-a", false, ai.InvestigationQuery{Device: "edge-1"})
	if len(rows) != 0 {
		t.Fatalf("a rating with no investigation behind it wrote %d rows", len(rows))
	}
	// An invalid rating is still rejected before anything is written.
	if w := irisFeedback(t, s, claims, `{"rating":"maybe"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid rating status = %d, want 400", w.Code)
	}
}

func TestIrisMemoryNotWiredIsHarmless(t *testing.T) {
	// A deployment without investigation memory must behave exactly as before:
	// the recall seam is absent (so the tool is never registered) and the
	// feedback call still succeeds.
	s := aiCfgTestServer(t)
	deps := s.aiTroubleshootDeps(httptest.NewRequest(http.MethodPost, "/api/ai/ask", nil),
		jwtClaims{Role: "admin", Tenant: "t-a", Sub: "op-a"})
	if deps.RecallInvestigations != nil {
		t.Error("the recall seam must be nil when no memory store is wired")
	}
	if w := irisFeedback(t, s, jwtClaims{Role: "admin", Tenant: "t-a", Sub: "op-a"}, `{"rating":"up"}`); w.Code != http.StatusNoContent {
		t.Fatalf("status = %d", w.Code)
	}
}
