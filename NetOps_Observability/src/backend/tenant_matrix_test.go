// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"testing"
)

// TestTenantMatrixIsolation is the uniform cross-tenant regression net: for
// every tenant-scoped resource type, drive the REAL router and assert that
// tenant A's data is invisible and immutable to tenant B, while the platform
// owner sees everything. A new resource type added without isolation should make
// this fail. Complements the policy-level authz_test.go and the per-resource
// suites.
func TestTenantMatrixIsolation(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token // seeded platform owner

	mkUser := func(user, tenant string) string {
		st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "super-admin", "tenant_id": tenant,
		})
		if st != 201 {
			t.Fatalf("create %s: %d %s", user, st, b)
		}
		return login(t, srv, user, "Passw0rd!2345").Token
	}
	alice := mkUser("alice", "acme")
	bob := mkUser("bob", "globex")

	asString := func(v any) string { s, _ := v.(string); return s }

	extractID := func(b []byte, path string) string {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("decode create response: %v (%s)", err, b)
		}
		if path == "key.id" { // api-key create wraps the record under "key"
			if k, ok := m["key"].(map[string]any); ok {
				return asString(k["id"])
			}
			return ""
		}
		return asString(m[path])
	}
	countMatching := func(token, listPath, id string) (matching int) {
		st, b := do(t, srv, "GET", listPath, token, nil)
		if st != 200 {
			t.Fatalf("list %s: %d (%s)", listPath, st, b)
		}
		var arr []map[string]any
		if err := json.Unmarshal(b, &arr); err != nil {
			t.Fatalf("decode list %s: %v", listPath, err)
		}
		for _, o := range arr {
			if asString(o["id"]) == id {
				matching++
			}
		}
		return
	}

	specs := []struct {
		name       string
		path       string // create == list base; by-id == path + "/" + id
		createBody map[string]any
		idPath     string
		getByID    bool // resource exposes GET /{id}
	}{
		{"devices", "/api/devices", map[string]any{"id": "acme-router", "name": "acme-router"}, "id", true},
		{"saved objects", "/api/saved", map[string]any{"type": "saved_search", "name": "acme q", "body": map[string]any{}}, "id", true},
		{"snmp credentials", "/api/snmp/credentials", map[string]any{"name": "acme cred", "version": "v2c", "community": "s3cret"}, "id", false},
		{"api keys", "/api/apikeys", map[string]any{"label": "acme key"}, "key.id", false},
	}

	for _, sp := range specs {
		t.Run(sp.name, func(t *testing.T) {
			// alice (acme) creates one.
			st, b := do(t, srv, "POST", sp.path, alice, sp.createBody)
			if st != 201 {
				t.Fatalf("alice create %s: %d (%s)", sp.name, st, b)
			}
			id := extractID(b, sp.idPath)
			if id == "" {
				t.Fatalf("no id from %s create: %s", sp.name, b)
			}

			// alice sees it; bob sees none of alice's; platform owner sees it.
			if countMatching(alice, sp.path, id) != 1 {
				t.Errorf("alice should see her own %s", sp.name)
			}
			if countMatching(bob, sp.path, id) != 0 {
				t.Errorf("TENANT LEAK: bob (globex) sees alice's %s", sp.name)
			}
			if countMatching(admin, sp.path, id) != 1 {
				t.Errorf("platform owner should see the %s", sp.name)
			}

			// bob can neither read (where exposed) nor delete it by id → 404.
			byID := sp.path + "/" + id
			if sp.getByID {
				if st, _ := do(t, srv, "GET", byID, bob, nil); st != 404 {
					t.Errorf("bob GET %s by id: got %d want 404", sp.name, st)
				}
			}
			if st, _ := do(t, srv, "DELETE", byID, bob, nil); st != 404 {
				t.Errorf("bob DELETE %s by id: got %d want 404", sp.name, st)
			}
			// ...and it survives bob's attempt: platform owner still sees it.
			if countMatching(admin, sp.path, id) != 1 {
				t.Errorf("TENANT LEAK: bob mutated alice's %s", sp.name)
			}
		})
	}
}
