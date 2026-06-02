package main

import (
	"encoding/json"
	"testing"
)

// The audit trail records mutations + denials at the middleware chokepoint, and
// /api/audit is itself tenant-scoped: the platform owner sees all; a tenant
// admin sees only its own tenant's events.
func TestAuditTrail(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "password123").Token // platform owner (tenant "")

	st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "alice", "password": "password123", "role": "super-admin", "tenant_id": "acme",
	})
	if st != 201 {
		t.Fatalf("create alice: %d %s", st, b)
	}
	alice := login(t, srv, "alice", "password123").Token

	// A successful mutation by alice (recorded, tenant=acme).
	if st, b := do(t, srv, "POST", "/api/saved", alice, map[string]any{
		"type": "saved_search", "name": "q", "body": map[string]any{},
	}); st != 201 {
		t.Fatalf("alice create saved: %d %s", st, b)
	}
	// A cross-tenant probe by alice → 404 deny (recorded, tenant=acme).
	if st, _ := do(t, srv, "DELETE", "/api/devices/ghost", alice, nil); st != 404 {
		t.Fatalf("expected 404 for ghost delete, got %d", st)
	}

	events := func(token string) []map[string]any {
		st, b := do(t, srv, "GET", "/api/audit", token, nil)
		if st != 200 {
			t.Fatalf("audit GET: %d (%s)", st, b)
		}
		var out []map[string]any
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Platform owner sees alice's saved-object creation.
	foundSaved := false
	for _, e := range events(admin) {
		if e["actor"] == "alice" && e["method"] == "POST" && e["path"] == "/api/saved" {
			foundSaved = true
		}
	}
	if !foundSaved {
		t.Error("audit should record alice's POST /api/saved")
	}

	// alice (tenant admin) sees only her own tenant's events, and the deny is logged.
	mine := events(alice)
	if len(mine) == 0 {
		t.Fatal("alice should see her own audit events")
	}
	sawDeny := false
	for _, e := range mine {
		if tnt, _ := e["tenant"].(string); tnt != "acme" {
			t.Errorf("AUDIT LEAK: alice saw an event for tenant %q", tnt)
		}
		if e["path"] == "/api/devices/ghost" && e["decision"] == "deny" {
			sawDeny = true
		}
	}
	if !sawDeny {
		t.Error("audit should record alice's cross-tenant delete as a deny")
	}
}
