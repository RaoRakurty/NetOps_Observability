// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Route templates covered (the coverage guard matches this literal text):
//   "/api/tac/learning"  "/api/tac/learning/"

package backend

// tac_learning_isolation_test.go — §3a cross-org isolation guard for the TAC
// LEARNING BACKLOG and its signature CANDIDATES (tracker 243), exercised
// through the REAL router + auth middleware (org_isolation_test.go template).
//
// The obligations §3a rule 5 demands:
//
//	· own-only        — a tenant sees only its own candidates, and only its own
//	                    candidates are rendered into its export
//	· foreign → 404   — another org's candidate id is indistinguishable from an
//	                    id that does not exist; never 403, which would confirm it
//	· as_tenant       — an X-Acting-Tenant override into another org is ignored
//	· owner stamped   — the tenant comes from the TOKEN; a tenant_id in the body
//	                    is a 400, because the wire type cannot express one
//
// Plus the two properties this feature rests on, proven through HTTP and not
// only in the package:
//
//	· §7 is not relaxed for a proposal — a config/restart/daemon command is
//	  refused on the way into a candidate, naming the family and the rule;
//	· a candidate is NEVER promoted — the export is a file, the shipped
//	  knowledge surface is unchanged by writing one, and nothing on this API
//	  can put a candidate into the catalogue.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// candBody is the create/update payload. It deliberately mirrors the module's
// wire type: a field it does not carry (a tenant, an id, an owner) cannot be
// sent by accident.
func candBody(dialect, class, title string, commands ...string) map[string]any {
	cmds := make([]map[string]any, 0, len(commands))
	for _, c := range commands {
		cmds = append(cmds, map[string]any{"command": c})
	}
	return map[string]any{
		"dialect": dialect, "class_id": class, "title": title,
		"commands": cmds,
		"sources":  []map[string]any{{"url": "https://www.cisco.com/example", "title": "Vendor note"}},
		"answer":   "TAC said the peer was refused by an empty prefix-list.",
	}
}

func candID(t *testing.T, body []byte) string {
	t.Helper()
	var out struct {
		Candidate struct {
			ID string `json:"id"`
		} `json:"candidate"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode candidate: %v (%s)", err, body)
	}
	if out.Candidate.ID == "" {
		t.Fatalf("no candidate id in %s", body)
	}
	return out.Candidate.ID
}

func TestTACLearningCrossOrgIsolation(t *testing.T) {
	srv, _ := newTACTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "LRN Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "LRN Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "lrn-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user,
			token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	// ── own-only: each org writes its own candidate ─────────────────────────
	stA, bodyA := do(t, srv, "POST", "/api/tac/learning/candidates", a.token,
		candBody("cisco-iosxe", "bgp-session", "ACME peer stuck in Idle", "show ip bgp summary"))
	if stA != 201 {
		t.Fatalf("A writes its own candidate: %d %s", stA, bodyA)
	}
	idA := candID(t, bodyA)
	stB, bodyB := do(t, srv, "POST", "/api/tac/learning/candidates", b.token,
		candBody("cisco-iosxe", "bgp-session", "OTHER peer stuck in Idle", "show ip bgp summary"))
	if stB != 201 {
		t.Fatalf("B writes its own candidate: %d %s", stB, bodyB)
	}
	idB := candID(t, bodyB)

	st, list := do(t, srv, "GET", "/api/tac/learning", a.token, nil)
	if st != 200 {
		t.Fatalf("A reads its backlog: %d %s", st, list)
	}
	if !strings.Contains(string(list), "ACME peer stuck in Idle") {
		t.Fatalf("A cannot see its own candidate: %s", list)
	}
	if strings.Contains(string(list), "OTHER peer stuck in Idle") || strings.Contains(string(list), idB) {
		t.Fatal("CROSS-TENANT LEAK: A sees B's signature candidate")
	}

	// The EXPORT is the one surface that renders candidates as a file somebody
	// sends onward, so it gets its own leak check rather than inheriting the
	// listing's.
	st, exp := do(t, srv, "GET", "/api/tac/learning/export?dialect=cisco-iosxe", a.token, nil)
	if st != 200 {
		t.Fatalf("A exports: %d %s", st, exp)
	}
	if !strings.Contains(string(exp), "ACME peer stuck in Idle") {
		t.Fatalf("A's export is missing A's own candidate: %s", exp)
	}
	if strings.Contains(string(exp), "OTHER peer stuck in Idle") {
		t.Fatal("CROSS-TENANT LEAK: A's research export carries B's candidate")
	}

	// ── foreign id → 404 on every item verb, never 403 ─────────────────────
	for _, route := range []struct {
		method string
		body   map[string]any
	}{
		{"GET", nil},
		{"PUT", candBody("cisco-iosxe", "bgp-session", "hijacked", "show ip bgp summary")},
		{"DELETE", nil},
	} {
		st, body := do(t, srv, route.method, "/api/tac/learning/candidates/"+idB, a.token, route.body)
		if st != http.StatusNotFound {
			t.Errorf("%s another org's candidate: %d %s, want 404", route.method, st, body)
		}
	}
	// An id that does not exist at all answers IDENTICALLY — the subtree is not
	// an existence oracle.
	if st, _ := do(t, srv, "GET", "/api/tac/learning/candidates/cand-000000000000000000000000", a.token, nil); st != http.StatusNotFound {
		t.Fatalf("unknown candidate id: %d, want the same 404 a foreign id gets", st)
	}
	// B's candidate is untouched by A's attempts.
	if st, body := do(t, srv, "GET", "/api/tac/learning/candidates/"+idB, b.token, nil); st != 200 ||
		!strings.Contains(string(body), "OTHER peer stuck in Idle") {
		t.Fatalf("A's cross-tenant writes damaged B's candidate: %d %s", st, body)
	}

	// ── as_tenant / X-Acting-Tenant into another org is ignored ─────────────
	{
		payload, _ := json.Marshal(candBody("cisco-iosxe", "bgp-session", "smuggled", "show ip bgp summary"))
		req, err := http.NewRequest("POST", srv.URL+"/api/tac/learning/candidates", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+a.token)
		req.Header.Set("X-Acting-Tenant", b.tenantID)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 201 {
			// It may only have landed in A's own scope; assert B cannot see it.
			_, blist := do(t, srv, "GET", "/api/tac/learning", b.token, nil)
			if strings.Contains(string(blist), "smuggled") {
				t.Fatal("acting-tenant override wrote into another org's learning backlog")
			}
		}
	}

	// ── the owner is stamped from the token; a tenant in the body is a 400 ──
	forged := candBody("cisco-iosxe", "bgp-session", "forged", "show ip bgp summary")
	forged["tenant_id"] = b.tenantID
	if st, body := do(t, srv, "POST", "/api/tac/learning/candidates", a.token, forged); st != http.StatusBadRequest {
		t.Fatalf("a tenant smuggled into the body was not rejected: %d %s", st, body)
	}

	// ── A revises and drops its own candidate ──────────────────────────────
	if st, body := do(t, srv, "PUT", "/api/tac/learning/candidates/"+idA, a.token,
		candBody("cisco-iosxe", "bgp-session", "ACME peer stuck in Idle (revised)", "show ip bgp neighbors")); st != 200 {
		t.Fatalf("A revises its own candidate: %d %s", st, body)
	}
	if st, _ := do(t, srv, "DELETE", "/api/tac/learning/candidates/"+idA, a.token, nil); st != 200 {
		t.Fatalf("A deletes its own candidate: %d", st)
	}
}

// TestTACCandidateRefusesAForbiddenCommandByName — §7 is not relaxed for a
// proposal. An operator who is told "invalid" learns nothing; the refusal must
// name the line and the family that refused it.
func TestTACCandidateRefusesAForbiddenCommandByName(t *testing.T) {
	srv, _ := newTACTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "LRN Org C"})
	if st != 201 {
		t.Fatalf("org: %d %s", st, b)
	}
	st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "LRN Tenant C", "org_id": idOf(t, b)})
	if st != 201 {
		t.Fatalf("tenant: %d %s", st, b)
	}
	if st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "lrn-user-C", "password": "Passw0rd!2345", "role": "operator", "tenant_id": idOf(t, b),
	}); st != 201 {
		t.Fatalf("user: %d %s", st, b)
	}
	tok := login(t, srv, "lrn-user-C", "Passw0rd!2345").Token

	st, body := do(t, srv, "POST", "/api/tac/learning/candidates", tok,
		candBody("cisco-iosxe", "bgp-session", "bad proposal", "show ip bgp summary", "clear ip bgp *"))
	if st != http.StatusBadRequest {
		t.Fatalf("a candidate carrying a state-clearing command was saved: %d %s", st, body)
	}
	if !strings.Contains(string(body), "clear ip bgp") || !strings.Contains(string(body), "config") {
		t.Fatalf("the refusal does not name the line and its family: %s", body)
	}

	// A candidate changes NOTHING about what Correlix claims to know: the
	// knowledge surface before and after writing one is byte-identical.
	_, before := do(t, srv, "GET", "/api/troubleshoot/tac/knowledge", tok, nil)
	if st, b := do(t, srv, "POST", "/api/tac/learning/candidates", tok,
		candBody("cisco-iosxe", "bgp-graceful-restart-stall", "a class Correlix does not have", "show ip bgp summary")); st != 201 {
		t.Fatalf("a novel class must be allowed as a PROPOSAL: %d %s", st, b)
	}
	_, after := do(t, srv, "GET", "/api/troubleshoot/tac/knowledge", tok, nil)
	if string(before) != string(after) {
		t.Fatal("writing a signature candidate changed the shipped knowledge surface — a candidate is never promoted")
	}
}
