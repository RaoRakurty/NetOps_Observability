// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_learning_isolation_test.go — the Iris learning loop (tracker 337 N-F5)
// over HTTP: §3a isolation (a refresh reads only the caller's own tenant, the
// list is own-only, a foreign id → 404 for every verb, an as_tenant walk is
// ignored, a smuggled body tenant is refused, a Global view must choose a
// workspace) and that nothing activates without a second person — a fact
// adopted from a proposal is only PENDING until a different administrator
// approves it, an alias is written only by a person other than the adopter,
// and an API key can neither adopt nor approve.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/incidentfp"
	"netops/backend/internal/irislearning"
	"netops/backend/internal/rcaresolution"
)

// learningFixture is ctxFixture plus the learning store and three cEdge-80
// incidents in tenant A that operators recorded as fixed by a provider ticket.
func learningFixture(t *testing.T) (*server, http.Handler, jwtClaims, jwtClaims, jwtClaims) {
	t.Helper()
	s, h, alice, bob, reviewer := ctxFixture(t)
	s.irisLearning = irislearning.NewMemStore()
	s.rcaResolutions = rcaresolution.NewFileStore("")
	s.incidentFP = incidentfp.NewMemStore(100)
	tenantA, _ := principalTenant(alice)
	ctx := context.Background()
	for i, id := range []string{
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333",
	} {
		if err := s.incidentFP.Put(ctx, tenantA, incidentfp.Fingerprint{CorrelationID: id, Devices: []string{"cEdge-80"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.rcaResolutions.Add(ctx, tenantA, rcaresolution.Resolution{TenantID: tenantA, CorrelationID: id,
			Kind: rcaresolution.KindProviderTicket, Note: "Carrier X ticket", CreatedBy: "ua-noc",
			CreatedAt: time.Now().UTC().Add(-time.Duration(i+1) * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	return s, h, alice, bob, reviewer
}

func learningProposals(t *testing.T, h http.Handler, c jwtClaims) []map[string]any {
	t.Helper()
	code, m := ctxCall(t, h, c, http.MethodGet, "/api/ai/learning", "")
	if code != http.StatusOK {
		t.Fatalf("list: %d %v", code, m)
	}
	var out []map[string]any
	for _, p := range m["proposals"].([]any) {
		out = append(out, p.(map[string]any))
	}
	return out
}

func TestIrisLearningRefreshReadsOnlyTheCallersTenant(t *testing.T) {
	_, h, alice, bob, _ := learningFixture(t)
	if code, m := ctxCall(t, h, bob, http.MethodPost, "/api/ai/learning/refresh", ""); code != http.StatusOK || m["added"].(float64) != 0 {
		t.Fatalf("tenant B's refresh: %d %v (it must not see tenant A's resolutions)", code, m)
	}
	if code, m := ctxCall(t, h, alice, http.MethodPost, "/api/ai/learning/refresh", ""); code != http.StatusOK || m["added"].(float64) != 1 {
		t.Fatalf("tenant A's refresh: %d %v", code, m)
	}
	if ps := learningProposals(t, h, bob); len(ps) != 0 {
		t.Fatalf("tenant B lists tenant A's proposals: %v", ps)
	}
	ps := learningProposals(t, h, alice)
	if len(ps) != 1 || ps[0]["target"] != "org_context" || ps[0]["state"] != "proposed" {
		t.Fatalf("tenant A's proposals: %v", ps)
	}
	draft := ps[0]["context"].(map[string]any)["body"].(string)
	if strings.Contains(draft, "Carrier X") {
		t.Fatalf("an operator's note reached the draft: %q", draft)
	}
}

func TestIrisLearningForeignIdIsNotFound(t *testing.T) {
	_, h, alice, bob, _ := learningFixture(t)
	serveAs(h, alice, http.MethodPost, "/api/ai/learning/refresh", "")
	id := learningProposals(t, h, alice)[0]["id"].(string)
	walker := bob
	walker.ActingTenant = alice.Tenant
	for name, c := range map[string]jwtClaims{"other tenant": bob, "as_tenant walk": walker} {
		for _, p := range []struct{ method, path, body string }{
			{http.MethodGet, "/api/ai/learning/" + id + "?as_tenant=" + alice.Tenant, ""},
			{http.MethodPost, "/api/ai/learning/" + id + "/adopt", `{"body":"hijacked"}`},
			{http.MethodPost, "/api/ai/learning/" + id + "/approve", `{}`},
			{http.MethodPost, "/api/ai/learning/" + id + "/dismiss", `{"reason":"not ours"}`},
		} {
			if code, m := ctxCall(t, h, c, p.method, p.path, p.body); code != http.StatusNotFound {
				t.Fatalf("%s: %s %s → %d %v, want 404", name, p.method, p.path, code, m)
			}
		}
	}
	if ps := learningProposals(t, h, alice); ps[0]["state"] != "proposed" {
		t.Fatalf("a foreign caller changed tenant A's proposal: %v", ps[0])
	}
}

func TestIrisLearningRefusals(t *testing.T) {
	_, h, alice, _, reviewer := learningFixture(t)
	serveAs(h, alice, http.MethodPost, "/api/ai/learning/refresh", "")
	id := learningProposals(t, h, alice)[0]["id"].(string)

	global := alice
	global.Role, global.Tenant = "admin", ""
	if code, _ := ctxCall(t, h, global, http.MethodGet, "/api/ai/learning", ""); code != http.StatusBadRequest && code != http.StatusForbidden {
		t.Fatalf("a Global view listing proposals: %d, want it told to choose a workspace", code)
	}
	bot := reviewer
	bot.Sub = "apikey:k1"
	if code, _ := ctxCall(t, h, bot, http.MethodPost, "/api/ai/learning/"+id+"/adopt", `{}`); code != http.StatusForbidden {
		t.Fatalf("an API key adopting: %d, want 403", code)
	}
	if code, _ := ctxCall(t, h, alice, http.MethodPost, "/api/ai/learning/"+id+"/adopt", `{"tenant_id":"t-b","body":"x"}`); code != http.StatusBadRequest {
		t.Fatalf("a smuggled tenant in the body: %d, want 400", code)
	}
	if code, _ := ctxCall(t, h, alice, http.MethodPost, "/api/ai/learning/"+id+"/adopt", `{}`); code != http.StatusUnprocessableEntity {
		t.Fatalf("adopting with {{…}} still in the draft: %d, want 422", code)
	}
	if code, _ := ctxCall(t, h, reviewer, http.MethodPost, "/api/ai/learning/"+id+"/dismiss", `{"reason":""}`); code != http.StatusUnprocessableEntity {
		t.Fatalf("dismissing without a reason: %d, want 422", code)
	}
}

func TestIrisLearningFactNeedsASecondPerson(t *testing.T) {
	_, h, alice, _, reviewer := learningFixture(t)
	serveAs(h, alice, http.MethodPost, "/api/ai/learning/refresh", "")
	id := learningProposals(t, h, alice)[0]["id"].(string)
	body := "cEdge-80: its MPLS circuit is CX-7781, run by Carrier X; open tickets through the Carrier X NOC portal."
	code, m := ctxCall(t, h, alice, http.MethodPost, "/api/ai/learning/"+id+"/adopt", `{"body":`+jsonString(body)+`}`)
	if code != http.StatusOK || m["state"] != "adopted" || m["target_state"] != "pending" {
		t.Fatalf("adopt: %d %v", code, m)
	}
	if _, p := ctxCall(t, h, reviewer, http.MethodGet, "/api/ai/context/preview", ""); strings.Contains(p["block"].(string), "CX-7781") {
		t.Fatal("adopting activated the fact")
	}
	if code, _ := ctxCall(t, h, alice, http.MethodPost, "/api/ai/learning/"+id+"/approve", `{}`); code != http.StatusForbidden {
		t.Fatalf("the adopter approving their own fact: %d, want 403", code)
	}
	code, m = ctxCall(t, h, reviewer, http.MethodPost, "/api/ai/learning/"+id+"/approve", `{}`)
	if code != http.StatusOK || m["state"] != "applied" || m["target_state"] != "active" {
		t.Fatalf("a second administrator approving: %d %v", code, m)
	}
	if _, p := ctxCall(t, h, reviewer, http.MethodGet, "/api/ai/context/preview", ""); !strings.Contains(p["block"].(string), "CX-7781") {
		t.Fatalf("the approved fact is not what Iris reads: %v", p)
	}
}

func TestIrisLearningAliasNeedsASecondPerson(t *testing.T) {
	s, h, alice, bob, reviewer := learningFixture(t)
	tenantA, _ := principalTenant(alice)
	p := irislearning.Proposal{Target: irislearning.TargetAlias, Generator: irislearning.GenEntityCorrection,
		Subject: "alias|site|site:dfw-hq|big d", Title: "t", Why: "w",
		Alias: &irislearning.AliasDraft{EntityType: "site", EntityID: "site:dfw-hq", Alias: "big d"}}
	if _, _, err := s.irisLearning.Offer(context.Background(), tenantA, []irislearning.Proposal{p}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	id := learningProposals(t, h, alice)[0]["id"].(string)
	if code, m := ctxCall(t, h, alice, http.MethodPost, "/api/ai/learning/"+id+"/adopt", `{}`); code != http.StatusOK || m["state"] != "adopted" {
		t.Fatalf("adopt: %d %v", code, m)
	}
	if len(s.nlqAliases.List(tenantA, false)) != 0 {
		t.Fatal("adopting wrote the alias")
	}
	if code, _ := ctxCall(t, h, alice, http.MethodPost, "/api/ai/learning/"+id+"/approve", `{}`); code != http.StatusForbidden {
		t.Fatalf("the adopter approving their own alias: %d, want 403", code)
	}
	if code, m := ctxCall(t, h, reviewer, http.MethodPost, "/api/ai/learning/"+id+"/approve", `{}`); code != http.StatusOK || m["state"] != "applied" {
		t.Fatalf("a second administrator approving: %d %v", code, m)
	}
	got := s.nlqAliases.List(tenantA, false)
	if len(got) != 1 || got[0].Alias != "big d" {
		t.Fatalf("aliases of tenant A: %+v", got)
	}
	tenantB, _ := principalTenant(bob)
	if len(s.nlqAliases.List(tenantB, false)) != 0 {
		t.Fatal("tenant A's approval wrote an alias into tenant B")
	}
}

func TestIrisLearningWithoutPostgresIs503(t *testing.T) {
	s, h, alice, _, _ := learningFixture(t)
	s.irisLearning = nil
	if code, _ := ctxCall(t, h, alice, http.MethodGet, "/api/ai/learning", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("no store: %d, want 503", code)
	}
}
