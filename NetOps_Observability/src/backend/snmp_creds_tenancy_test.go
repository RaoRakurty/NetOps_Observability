package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/snmpcred"
	"testing"
)

// SNMP credentials are tenant-scoped: a scoped principal sees only its own; the
// global/untagged ones are platform-owned (visible cross-tenant only). Secrets,
// so a leak here is serious. Mirrors the device/saved isolation guarantees.
func snmpTenantServer(t *testing.T) *server {
	t.Helper()
	dir := t.TempDir()
	rs, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatal(err)
	}
	cs, err := snmpcred.NewStore(dir+"/snmp.json", nil, platformKV{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Upsert(snmpcred.Credential{ID: "acme-v2c", Name: "acme-v2c", TenantID: "acme", Version: "v2c", Community: "s3cret"}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Upsert(snmpcred.Credential{ID: "platform-v2c", Name: "platform-v2c", Version: "v2c", Community: "rootpw"}); err != nil {
		t.Fatal(err) // no tenant => global/platform-owned
	}
	return &server{roles: rs, snmpCreds: cs}
}

func TestSNMPCredsTenantScoped(t *testing.T) {
	s := snmpTenantServer(t)

	list := func(claims jwtClaims) []snmpcred.Public {
		w := httptest.NewRecorder()
		s.handleSNMPCreds(w, req("GET", "/api/snmp/credentials", "", claims))
		if w.Code != http.StatusOK {
			t.Fatalf("list: %d (%s)", w.Code, w.Body.String())
		}
		var out []snmpcred.Public
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// acme (scoped) sees only its own credential — never the platform/global one.
	acme := list(jwtClaims{Sub: "a@acme", Role: RoleSuperAdmin, Tenant: "acme"})
	if len(acme) != 1 || acme[0].ID != "acme-v2c" {
		t.Fatalf("tenant leak: acme should see only acme-v2c, got %+v", acme)
	}

	// Platform owner sees both.
	owner := list(jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal})
	if len(owner) != 2 {
		t.Fatalf("platform owner should see all 2 creds, got %d", len(owner))
	}

	// acme cannot delete the platform credential — 404 (no existence leak), and
	// it survives.
	w := httptest.NewRecorder()
	s.handleSNMPCredByID(w, req("DELETE", "/api/snmp/credentials/platform-v2c", "", jwtClaims{Sub: "a@acme", Role: RoleSuperAdmin, Tenant: "acme"}))
	if w.Code != http.StatusNotFound {
		t.Fatalf("acme deleting platform cred: got %d, want 404", w.Code)
	}
	if _, ok := s.snmpCreds.Get("platform-v2c"); !ok {
		t.Fatal("TENANT LEAK: acme deleted the platform credential")
	}

	// A scoped create is forced into the caller's tenant even if it asks otherwise.
	w = httptest.NewRecorder()
	s.handleSNMPCreds(w, req("POST", "/api/snmp/credentials", `{"name":"sneaky","version":"v2c","community":"x","tenant_id":"globex"}`, jwtClaims{Sub: "a@acme", Role: RoleSuperAdmin, Tenant: "acme"}))
	if w.Code != http.StatusCreated {
		t.Fatalf("scoped create: %d (%s)", w.Code, w.Body.String())
	}
	var made snmpcred.Public
	if err := json.Unmarshal(w.Body.Bytes(), &made); err != nil {
		t.Fatal(err)
	}
	if made.TenantID != "acme" {
		t.Fatalf("scoped create must be forced into caller's tenant, got %q", made.TenantID)
	}
}
