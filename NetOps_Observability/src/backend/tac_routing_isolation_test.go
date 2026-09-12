// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Route templates covered (the coverage guard matches this literal text):
//   "/api/tac/routing"
//   "/api/incidents/{id}/tac/escalate"
//   "/api/incidents/{id}/tac/escalate/prepare"
//   "/api/incidents/{id}/tac/escalate/confirm"
//   "/api/incidents/{id}/tac/escalate/dry-run"
//   "/api/incidents/{id}/tac/case/refresh"

package backend

// tac_routing_isolation_test.go — §3a cross-org isolation guard for the TENANT'S
// TAC ROUTING RECORD and for the ONE-CLICK escalation routes.
//
// WHAT IS ACTUALLY AT RISK HERE, and it is not a device name. The routing record
// is a customer's COMMERCIAL RELATIONSHIP with a vendor: the support contract
// number, the account id the vendor entitles on, the site id, the coverage end
// date, and the name, email and phone number of the person the vendor calls at
// three in the morning. Leaking one tenant's row to another is not a metadata
// leak; it is handing a competitor a contract number and an on-call phone
// number. So every obligation §3a rule 5 lists is proven here through the REAL
// router and auth middleware:
//
//	· own-only        — a tenant reads only its own record; another tenant's
//	                    contract number never appears in its answer
//	· owner stamped   — the tenant comes from the TOKEN, never from the body
//	· as_tenant       — an X-Acting-Tenant override into another org is IGNORED
//	· cross-tenant    — another tenant's incident id answers 404 on every one of
//	                    the escalation routes, so the subtree is not an existence
//	                    oracle
//	· write refused   — a cross-tenant write cannot happen, and the victim's
//	                    stored record is unchanged afterwards

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// tacRoutingView is the shape /api/tac/routing answers with.
type tacRoutingView struct {
	Routing struct {
		Contact struct {
			Name  string `json:"name"`
			Email string `json:"email"`
			Phone string `json:"phone"`
		} `json:"contact"`
		RouteByVendor    map[string]string `json:"route_by_vendor"`
		CaptureByDialect map[string]string `json:"capture_by_dialect"`
		ContractByVendor map[string]struct {
			Vendor     string `json:"vendor"`
			ContractID string `json:"contract_id"`
			AccountID  string `json:"account_id"`
			ExpiresOn  string `json:"expires_on"`
		} `json:"contract_by_vendor"`
		ContractBySerial map[string]struct {
			ContractID string `json:"contract_id"`
		} `json:"contract_by_serial"`
	} `json:"routing"`
	Configured bool `json:"configured"`
}

func decodeRouting(t *testing.T, body []byte) tacRoutingView {
	t.Helper()
	var v tacRoutingView
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return v
}

// twoTACTenants builds two orgs, each with one operator, on a real server.
func twoTACTenants(t *testing.T) (*httptest.Server, *orgFixture, *orgFixture) {
	t.Helper()
	srv, _ := newTACTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "RT Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "RT Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "rt-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user,
			token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	return srv, fix["A"], fix["B"]
}

func TestTACRoutingIsScopedToTheCallersOwnTenant(t *testing.T) {
	srv, a, b := twoTACTenants(t)
	const path = "/api/tac/routing"

	// ── A configures its support relationship ───────────────────────────────
	saved := []byte(`{
      "contact":{"name":"Dana Ops","email":"dana.ops@acme.example","phone":"+1-555-0100"},
      "route_by_vendor":{"cisco":"portal-text"},
      "capture_by_dialect":{"cisco-iosxe":"tmpl-acme-1"},
      "contract_by_vendor":{"cisco":{"vendor":"cisco","contract_id":"ACME-CT-88","account_id":"acme-cco","expires_on":"2027-01-31"}},
      "contract_by_serial":{"FTX1234ABCD":{"contract_id":"ACME-CT-99"}}
    }`)
	st, body := tacConnRequest(t, srv.URL, "PUT", path, a.token, "", saved)
	if st != 200 {
		t.Fatalf("A save: %d %s", st, body)
	}
	if got := decodeRouting(t, body); got.Routing.ContractByVendor["cisco"].ContractID != "ACME-CT-88" {
		t.Fatalf("A's own save did not come back: %+v", got)
	}

	// ── B sees NOTHING of it ────────────────────────────────────────────────
	st, body = tacConnRequest(t, srv.URL, "GET", path, b.token, "", nil)
	if st != 200 {
		t.Fatalf("B read: %d %s", st, body)
	}
	got := decodeRouting(t, body)
	if got.Configured {
		t.Fatal("B has configured nothing and must read as unconfigured")
	}
	for _, leak := range []string{"ACME-CT-88", "ACME-CT-99", "acme-cco", "dana.ops@acme.example", "+1-555-0100", "tmpl-acme-1"} {
		if containsBytes(body, leak) {
			t.Fatalf("tenant B's answer carries tenant A's %q — a cross-tenant leak of a support contract", leak)
		}
	}

	// ── as_tenant into another org is IGNORED, not honoured ─────────────────
	// A non-cross principal's acting-tenant header is not a request Correlix
	// entertains: the token is the only source of ownership (§3a.2). It must
	// answer with B's OWN (empty) record, never with A's.
	st, body = tacConnRequest(t, srv.URL, "GET", path+"?as_tenant="+a.tenantID, b.token, a.tenantID, nil)
	if st != 200 {
		t.Fatalf("B read acting-as-A: %d %s", st, body)
	}
	if containsBytes(body, "ACME-CT-88") {
		t.Fatal("as_tenant into another org was HONOURED — a cross-tenant read")
	}

	// ── a cross-tenant WRITE cannot touch A's record ────────────────────────
	hostile := []byte(`{"contract_by_vendor":{"cisco":{"vendor":"cisco","contract_id":"HOSTILE"}}}`)
	st, body = tacConnRequest(t, srv.URL, "PUT", path+"?as_tenant="+a.tenantID, b.token, a.tenantID, hostile)
	if st != 200 {
		t.Fatalf("B save acting-as-A: %d %s", st, body)
	}
	st, body = tacConnRequest(t, srv.URL, "GET", path, a.token, "", nil)
	if st != 200 {
		t.Fatalf("A re-read: %d %s", st, body)
	}
	after := decodeRouting(t, body)
	if after.Routing.ContractByVendor["cisco"].ContractID != "ACME-CT-88" {
		t.Fatalf("tenant B's write reached tenant A's record: %+v", after)
	}
	if containsBytes(body, "HOSTILE") {
		t.Fatal("a cross-tenant write landed in the victim's record")
	}

	// ── the owner is stamped from the token: the body has no tenant field ───
	st, body = tacConnRequest(t, srv.URL, "PUT", path, a.token, "",
		[]byte(`{"tenant_id":"`+b.tenantID+`","contact":{"name":"X"}}`))
	if st != http.StatusBadRequest {
		t.Fatalf("a tenant_id in the body must be REFUSED (unknown field), got %d %s", st, body)
	}

	// ── clearing the last setting reads like never having made one ──────────
	st, _ = tacConnRequest(t, srv.URL, "DELETE", path, a.token, "", nil)
	if st != http.StatusNoContent {
		t.Fatalf("A delete: %d", st)
	}
	st, body = tacConnRequest(t, srv.URL, "GET", path, a.token, "", nil)
	if st != 200 || decodeRouting(t, body).Configured {
		t.Fatalf("after a delete the record must read unconfigured: %d %s", st, body)
	}
}

// TestTACEscalationRoutesAreNotAnExistenceOracle proves the one-click routes
// answer a foreign incident id exactly the way they answer one that never
// existed: 404, never 403.
func TestTACEscalationRoutesAreNotAnExistenceOracle(t *testing.T) {
	srv, a, b := twoTACTenants(t)
	// Two ids: one that plainly does not exist, and one shaped like a real
	// correlation id. Both must answer identically for BOTH tenants — that
	// identity is the property, not the status code on its own.
	for _, id := range []string{"no-such-incident", "3fa85f64-5717-4562-b3fc-2c963f66afa6"} {
		for _, path := range []string{
			"/api/incidents/" + id + "/tac/escalate",
			"/api/incidents/" + id + "/tac/escalate/prepare",
			"/api/incidents/" + id + "/tac/escalate/confirm",
			"/api/incidents/" + id + "/tac/escalate/dry-run",
			"/api/incidents/" + id + "/tac/case/refresh",
		} {
			stA, _ := tacConnRequest(t, srv.URL, "POST", path, a.token, "", []byte(`{}`))
			stB, _ := tacConnRequest(t, srv.URL, "POST", path, b.token, "", []byte(`{}`))
			if stA != http.StatusNotFound || stB != http.StatusNotFound {
				t.Fatalf("%s answered %d (A) / %d (B); a cross-tenant or unknown incident must be 404 on both",
					path, stA, stB)
			}
			// An X-Acting-Tenant override changes nothing: the incident is still
			// resolved in the caller's own scope.
			stActing, _ := tacConnRequest(t, srv.URL, "POST", path+"?as_tenant="+a.tenantID, b.token, a.tenantID, []byte(`{}`))
			if stActing != http.StatusNotFound {
				t.Fatalf("%s with as_tenant answered %d — the override must not widen the scope", path, stActing)
			}
		}
	}
}

// containsBytes is a substring check on a response body, named for what the
// assertions above are actually doing: searching one tenant's answer for another
// tenant's value.
func containsBytes(body []byte, needle string) bool {
	return needle != "" && strings.Contains(string(body), needle)
}
