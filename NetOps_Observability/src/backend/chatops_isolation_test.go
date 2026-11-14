// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// chatops_isolation_test.go — Iris in Slack / Teams (tracker 337 N-I6), the
// server seam: the §3a isolation of the admin/link API over the real routes,
// the JWT exemption covering ONLY the two signed inbound paths, and the asker
// running a chat question as the linked user in that user's own tenant —
// never as the platform owner, never across tenants, never with more
// permissions than the user's role holds.
//
// The protocol, the link state machine and the signature checks are proven in
// internal/chatops.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/chatops"
)

func chatopsFixture(t *testing.T) (*server, http.Handler, jwtClaims, jwtClaims) {
	t.Helper()
	t.Setenv("FEATURE_AI", "true")
	s, h, a, b := aiEntFixture(t)
	a.Sub, b.Sub = "ua-alice", "ub-bob"
	s.chatops = s.newChatops() // the file backend → the tenant-keyed MemStore
	return s, h, a, b
}

const chatopsSlackBody = `{"workspace_id":"T0ALPHA","signing_secret":"abababababababababababababababab","bot_token":"xoxb-1111-AAAAAAAAAA","enabled":true}`

func TestChatopsAPIIsolation(t *testing.T) {
	_, h, alice, bob := chatopsFixture(t)
	if code, m := ctxCall(t, h, alice, http.MethodPut, "/api/chatops/connections/slack", chatopsSlackBody); code != http.StatusOK {
		t.Fatalf("tenant A connects Slack: %d %v", code, m)
	}
	if _, m := ctxCall(t, h, alice, http.MethodGet, "/api/chatops/connections", ""); len(m["connections"].([]any)) != 1 {
		t.Fatalf("tenant A lists its own connection: %v", m)
	}
	walker := bob
	walker.ActingTenant = alice.Tenant // never honoured for a non-owner
	for name, c := range map[string]jwtClaims{"other tenant": bob, "as_tenant walk": walker} {
		if _, m := ctxCall(t, h, c, http.MethodGet, "/api/chatops/connections?as_tenant="+alice.Tenant, ""); len(m["connections"].([]any)) != 0 {
			t.Errorf("%s listed tenant A's connection: %v", name, m)
		}
		if code, _ := ctxCall(t, h, c, http.MethodDelete, "/api/chatops/connections/slack", ""); code != http.StatusNotFound {
			t.Errorf("%s deleting tenant A's connection: want 404, got %d", name, code)
		}
		if _, m := ctxCall(t, h, c, http.MethodGet, "/api/chatops/links", ""); len(m["links"].([]any)) != 0 {
			t.Errorf("%s listed tenant A's links: %v", name, m)
		}
		if code, _ := ctxCall(t, h, c, http.MethodPost, "/api/chatops/links/00000000-0000-4000-8000-000000000000/approve", ""); code != http.StatusNotFound {
			t.Errorf("%s approving an unknown link: want 404, got %d", name, code)
		}
	}
	// A tenant in the body is not a field: it is neither read nor honoured.
	smuggled := strings.Replace(chatopsSlackBody, `{`, `{"tenant_id":"`+alice.Tenant+`",`, 1)
	if code, _ := ctxCall(t, h, bob, http.MethodPut, "/api/chatops/connections/slack", smuggled); code != http.StatusOK {
		t.Fatalf("tenant B saving its own connection: %d", code)
	}
	if _, m := ctxCall(t, h, alice, http.MethodGet, "/api/chatops/connections", ""); len(m["connections"].([]any)) != 1 {
		t.Fatalf("tenant B's save must not touch tenant A: %v", m)
	}
	viewer := alice
	viewer.Role = "viewer"
	if code, _ := ctxCall(t, h, viewer, http.MethodGet, "/api/chatops/connections", ""); code != http.StatusForbidden {
		t.Errorf("a non-admin reading connections: want 403, got %d", code)
	}
	owner := jwtClaims{Sub: "root", Role: "super-admin", Tenant: ""}
	if code, _ := ctxCall(t, h, owner, http.MethodGet, "/api/chatops/connections", ""); code != http.StatusBadRequest && code != http.StatusForbidden {
		t.Errorf("the platform owner's all-tenants view must choose a workspace: got %d", code)
	}
	if code, _ := ctxCall(t, h, owner, http.MethodPost, "/api/chatops/link-code", `{"code":"ABCD-EFGH"}`); code != http.StatusForbidden {
		t.Errorf("the platform owner cannot link a chat account: got %d", code)
	}
}

// TestChatopsInboundIsTheOnlyJWTExemption: the two signed inbound paths pass
// the auth middleware without a token (and then answer 404 while the switch is
// off); the admin and link API do not.
func TestChatopsInboundIsTheOnlyJWTExemption(t *testing.T) {
	s, h, _, _ := chatopsFixture(t)
	srv := httptest.NewServer(s.withAuth(h))
	defer srv.Close()
	for path, want := range map[string]int{
		"/api/chatops/slack/0123456789abcdef0123456789abcdef": http.StatusNotFound,
		"/api/chatops/teams/0123456789abcdef0123456789abcdef": http.StatusNotFound,
		"/api/chatops/connections":                            http.StatusUnauthorized,
		"/api/chatops/link-code":                              http.StatusUnauthorized,
		"/api/chatops/me":                                     http.StatusUnauthorized,
	} {
		resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close() // status is all this test reads
		if resp.StatusCode != want {
			t.Errorf("POST %s without a token: want %d, got %d", path, want, resp.StatusCode)
		}
	}
}

// TestChatopsAskRunsAsTheLinkedUserOnly is the asker's contract.
func TestChatopsAskRunsAsTheLinkedUserOnly(t *testing.T) {
	s, _, alice, bob := chatopsFixture(t)
	ua, err := s.users.CreateFull(User{Username: "chat-alice", Role: "operator", TenantID: alice.Tenant}, "Passw0rd!2345")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := s.users.CreateFull(User{Username: "chat-root", Role: "super-admin", TenantID: ""}, "Passw0rd!2345")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	refused := func(name string, q chatops.Question) {
		t.Helper()
		_, err := s.chatopsAsk(ctx, q)
		var r chatops.Refusal
		if !errors.As(err, &r) {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
	}
	// The connection's tenant must be the linked user's own.
	refused("linked user asked through another tenant's app", chatops.Question{Tenant: bob.Tenant, UserID: ua.ID, Text: "what is going on right now?"})
	refused("the platform owner", chatops.Question{Tenant: alice.Tenant, UserID: owner.ID, Text: "what is going on right now?"})
	refused("an unknown user", chatops.Question{Tenant: alice.Tenant, UserID: "nobody", Text: "what is going on right now?"})
	if _, err := s.users.Update(ua.ID, User{Status: "disabled"}); err != nil {
		t.Fatal(err)
	}
	refused("a disabled user", chatops.Question{Tenant: alice.Tenant, UserID: ua.ID, Text: "what is going on right now?"})
	if _, err := s.users.Update(ua.ID, User{Status: "active"}); err != nil {
		t.Fatal(err)
	}
	// The linked user in their own tenant passes every gate (/help answers
	// without reading data, so this fixture needs no data stores).
	ans, err := s.chatopsAsk(ctx, chatops.Question{Tenant: alice.Tenant, UserID: ua.ID, Text: "/help"})
	if err != nil || ans.Text == "" {
		t.Fatalf("the linked user in their own tenant is answered: %+v %v", ans, err)
	}
	// The principal handed to the orchestrator is the user's own role and
	// tenant — a viewer's chat questions carry a viewer's permissions.
	viewer := jwtClaims{Sub: ua.ID, Role: "viewer", Tenant: alice.Tenant}
	p := s.aiPrincipal(viewer)
	if p.Cross || p.Tenant != alice.Tenant || p.Perms["administration:read"] {
		t.Errorf("a viewer's chat principal must not gain admin reads or cross-tenant reach: %+v", p)
	}
}
