package main

// cloud_connectors_org_test.go — Wave 5 #17 slice 2: org-level (multi-account)
// onboarding through the REAL router + auth middleware. Covers the anchor
// lifecycle (set / validate / render / clear), org-rooted scope discovery
// through the broker + adapter seam, and the MANDATED §3a isolation surface:
// a cross-tenant caller can neither read nor set another tenant's org anchor
// (404, never 403 — the id must not be revealed to exist).

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"netops/backend/cloudconn"
)

// orgFakeAdapter extends the broker test fake with a discoverable org surface:
// it records the Root the handler passed and returns two member accounts.
type orgFakeAdapter struct {
	*fakeAdapter
	lastRoot cloudconn.Scope
}

func (f *orgFakeAdapter) DiscoverScopes(_ context.Context, req cloudconn.DiscoverRequest) ([]cloudconn.Scope, error) {
	f.lastRoot = req.Root
	return []cloudconn.Scope{
		{Type: cloudconn.ScopeAccount, Ref: "111122223333", Display: "management", Discovered: true},
		{Type: cloudconn.ScopeAccount, Ref: "444455556666", Display: "member-prod", Discovered: true},
	}, nil
}

func TestConnectorOrgAnchorLifecycleAndIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.cloudConn = cloudconn.NewMemStore()
	fake := &orgFakeAdapter{fakeAdapter: &fakeAdapter{provider: cloudconn.ProviderAWS}}
	s.cloudBroker = cloudconn.NewIdentityBroker(s.cloudConn, s.vault, nil)
	s.cloudBroker.SetAdapter(func(cloudconn.Provider) cloudconn.CloudIdentityProvider { return fake })

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Two tenants, each with an operator (the §3a two-tenant template).
	type tenantFix struct{ token, connID string }
	fix := map[string]*tenantFix{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "OrgT " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "TenantOrg " + name, "org_id": idOf(t, b)})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tid := idOf(t, b)
		user := "orgop-" + name
		if st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tid,
		}); st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &tenantFix{token: login(t, srv, user, "Passw0rd!2345").Token}
	}

	// Tenant A creates an AWS connector.
	st, b := do(t, srv, "POST", "/api/cloud/connectors", fix["A"].token, map[string]any{
		"provider": "aws", "display_name": "Org-wide prod",
	})
	if st != 201 {
		t.Fatalf("create connector: %d %s", st, b)
	}
	var view cloudConnectorView
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	fix["A"].connID = view.ID
	orgPath := "/api/cloud/connectors/" + view.ID + "/org"

	// A member scope type is NOT an org anchor → 400, honest code.
	if st, b = do(t, srv, "POST", orgPath, fix["A"].token, map[string]any{"type": "account", "ref": "123456789012"}); st != 400 {
		t.Fatalf("member-type anchor must 400, got %d %s", st, b)
	}
	// A cross-provider anchor type is rejected too.
	if st, _ = do(t, srv, "POST", orgPath, fix["A"].token, map[string]any{"type": "mgmt_group", "ref": "mg"}); st != 400 {
		t.Fatalf("cross-provider anchor must 400, got %d", st)
	}

	// Set a valid OU anchor with a custom role template.
	st, b = do(t, srv, "POST", orgPath, fix["A"].token, map[string]any{
		"type": "ou", "ref": "ou-a1b2-c3d4e5", "role_template": "acme-observer",
	})
	if st != 200 {
		t.Fatalf("set org anchor: %d %s", st, b)
	}
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Identity.Org == nil || view.Identity.Org.Type != cloudconn.ScopeOU ||
		view.Identity.Org.Ref != "ou-a1b2-c3d4e5" || view.Identity.Org.RoleTemplate != "acme-observer" {
		t.Fatalf("org anchor not echoed on the view: %+v", view.Identity.Org)
	}

	// §3a: tenant B can neither read nor set A's org anchor — 404 both ways.
	if st, _ = do(t, srv, "GET", "/api/cloud/connectors/"+view.ID, fix["B"].token, nil); st != 404 {
		t.Fatalf("cross-tenant GET must 404, got %d", st)
	}
	if st, _ = do(t, srv, "POST", orgPath, fix["B"].token, map[string]any{"type": "org", "ref": "o-hijack"}); st != 404 {
		t.Fatalf("cross-tenant org POST must 404, got %d", st)
	}
	// The anchor is unchanged after the cross-tenant attempt.
	if st, b = do(t, srv, "GET", "/api/cloud/connectors/"+view.ID, fix["A"].token, nil); st != 200 {
		t.Fatalf("owner GET: %d", st)
	}
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Identity.Org == nil || view.Identity.Org.Ref != "ou-a1b2-c3d4e5" {
		t.Fatalf("anchor mutated by cross-tenant attempt: %+v", view.Identity.Org)
	}

	// Setup bundle renders the ORG artifacts (StackSet + enumeration note).
	if st, b = do(t, srv, "GET", "/api/cloud/connectors/"+view.ID+"/setup", fix["A"].token, nil); st != 200 {
		t.Fatalf("setup: %d %s", st, b)
	}
	if !strings.Contains(string(b), "StackSet") || !strings.Contains(string(b), "organizations:ListAccounts") {
		t.Fatalf("org setup artifacts missing from bundle: %.300s", b)
	}
	if !strings.Contains(string(b), "acme-observer") {
		t.Fatal("setup bundle must use the operator's role template")
	}

	// Auth + validate so the broker may mint (fake adapter → live_verified).
	if st, b = do(t, srv, "POST", "/api/cloud/connectors/"+view.ID+"/auth", fix["A"].token, map[string]any{
		"method": "cloud_role", "role_arn": "arn:aws:iam::111122223333:role/acme-observer",
	}); st != 200 {
		t.Fatalf("auth: %d %s", st, b)
	}
	if st, b = do(t, srv, "POST", "/api/cloud/connectors/"+view.ID+"/validate", fix["A"].token, nil); st != 200 {
		t.Fatalf("validate: %d %s", st, b)
	}

	// Discover: the handler roots enumeration on the ORG anchor and reports the
	// member scope type; the discovered accounts come back for SELECTION only.
	st, b = do(t, srv, "POST", "/api/cloud/connectors/"+view.ID+"/discover-scopes", fix["A"].token, nil)
	if st != 200 {
		t.Fatalf("discover: %d %s", st, b)
	}
	var disc struct {
		LiveCheck       string                    `json:"live_check"`
		Discovered      []cloudconn.Scope         `json:"discovered"`
		OrgScope        *cloudconn.OrgScopeAnchor `json:"org_scope"`
		MemberScopeType string                    `json:"member_scope_type"`
	}
	if err := json.Unmarshal(b, &disc); err != nil {
		t.Fatalf("decode discover: %v", err)
	}
	if disc.LiveCheck != "ok" {
		t.Fatalf("live_check = %q body=%s", disc.LiveCheck, b)
	}
	if disc.OrgScope == nil || disc.OrgScope.Ref != "ou-a1b2-c3d4e5" || disc.MemberScopeType != "account" {
		t.Fatalf("org metadata missing on discover response: %s", b)
	}
	if len(disc.Discovered) != 2 || disc.Discovered[1].Ref != "444455556666" {
		t.Fatalf("discovered = %+v", disc.Discovered)
	}
	if fake.lastRoot.Type != cloudconn.ScopeOU || fake.lastRoot.Ref != "ou-a1b2-c3d4e5" {
		t.Fatalf("adapter must be rooted on the org anchor, got %+v", fake.lastRoot)
	}
	// Discovery must NOT have widened the stored collection scope (§: operator
	// selects; enumeration is advisory).
	if st, b = do(t, srv, "GET", "/api/cloud/connectors/"+view.ID, fix["A"].token, nil); st != 200 {
		t.Fatalf("reload: %d", st)
	}
	if err := json.Unmarshal(b, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(view.Scopes) != 0 {
		t.Fatalf("discovery silently widened scopes: %+v", view.Scopes)
	}

	// Clearing: empty type returns the connector to single-account mode.
	// (Fresh struct: an omitted json field must not inherit the old pointer.)
	if st, b = do(t, srv, "POST", orgPath, fix["A"].token, map[string]any{"type": ""}); st != 200 {
		t.Fatalf("clear org anchor: %d %s", st, b)
	}
	var cleared cloudConnectorView
	if err := json.Unmarshal(b, &cleared); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cleared.Identity.Org != nil {
		t.Fatalf("org anchor not cleared: %+v", cleared.Identity.Org)
	}
}
