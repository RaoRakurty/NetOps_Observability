package backend

// protocol_diagnostics_isolation_test.go — §3a cross-org isolation guard for the
// protocol-diagnostics collect surface, exercised through the REAL router + auth
// middleware (org_isolation_test.go template). Asserts: an operator collects from
// its OWN device (200), a cross-tenant device id is a 404 (existence never
// revealed), an X-Acting-Tenant override into another org is ignored for a
// non-owner, and the platform owner can reach both.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"netops/backend/internal/protocoldiag"
	"netops/backend/models"
)

func TestProtocolDiagCollectCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)

	// The collect handler runs an issue bundle through the injected runner. A
	// MemCommandRunner ignores the device and returns "" for unmapped commands, so
	// collection succeeds with empty (but honest) outputs — enough to prove the
	// device-scope gate without a real transport.
	col, err := protocoldiag.NewCollector(protocoldiag.DefaultCatalog(), protocoldiag.MemCommandRunner{})
	if err != nil {
		t.Fatal(err)
	}
	s.protocolCollector = col

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// ── orgs A and B, each: org → tenant → tenant-scoped operator ────────────────
	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "PD Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "PD Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "pd-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	// One device per tenant — the collection's tenant is stamped from the DEVICE.
	s.discovery.Upsert(models.Device{ID: "pd-dev-a", Name: "pd-dev-a", OS: "Cisco IOS-XE", TenantID: a.tenantID})
	s.discovery.Upsert(models.Device{ID: "pd-dev-b", Name: "pd-dev-b", OS: "Cisco IOS-XE", TenantID: b.tenantID})

	collect := func(token, deviceID string) int {
		t.Helper()
		st, _ := do(t, srv, "POST", "/api/troubleshoot/protocol-diagnostics/collect", token,
			map[string]any{"device_id": deviceID, "issue_id": "ospf-neighbor-stuck"})
		return st
	}

	// ── own-tenant collect works ────────────────────────────────────────────────
	if st := collect(a.token, "pd-dev-a"); st != 200 {
		t.Fatalf("A collect own device: %d, want 200", st)
	}
	if st := collect(b.token, "pd-dev-b"); st != 200 {
		t.Fatalf("B collect own device: %d, want 200", st)
	}

	// ── cross-tenant device id → 404 (existence never revealed) ─────────────────
	if st := collect(a.token, "pd-dev-b"); st != http.StatusNotFound {
		t.Fatalf("A collect B's device: %d, want 404", st)
	}
	if st := collect(b.token, "pd-dev-a"); st != http.StatusNotFound {
		t.Fatalf("B collect A's device: %d, want 404", st)
	}

	// ── X-Acting-Tenant override into another org is ignored for a non-owner ─────
	{
		bts, _ := json.Marshal(map[string]any{"device_id": "pd-dev-b", "issue_id": "ospf-neighbor-stuck"})
		req, err := http.NewRequest("POST", srv.URL+"/api/troubleshoot/protocol-diagnostics/collect", bytes.NewReader(bts))
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
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("acting-tenant override must not widen a scoped caller: %d", resp.StatusCode)
		}
	}

	// ── platform owner reaches both devices ─────────────────────────────────────
	if st := collect(admin, "pd-dev-a"); st != 200 {
		t.Fatalf("owner collect A's device: %d, want 200", st)
	}
	if st := collect(admin, "pd-dev-b"); st != 200 {
		t.Fatalf("owner collect B's device: %d, want 200", st)
	}
}

// TestProtocolDiagAnalyzeTenantInvariantAndBodyTenantRejected pins the two
// properties the ledger's "globalRef" classification of analyze rests on:
//
//  1. TENANT-INVARIANCE — analyze reads no store and persists nothing, so two
//     operators in DIFFERENT orgs sending the identical request get the
//     byte-identical response. If this ever fails, analyze has started serving
//     tenant-variant data and must be reclassified "scoped" with a cross-org
//     isolation test.
//  2. §3a.2 — the tenant is never taken from the request body: a payload that
//     tries to smuggle one in is rejected outright (DisallowUnknownFields).
func TestProtocolDiagAnalyzeTenantInvariantAndBodyTenantRejected(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Two orgs, each with its own tenant-scoped operator.
	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "PDA Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "PDA Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "pda-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}

	payload := map[string]any{
		"issue_id": "ospf-neighbor-stuck",
		"device":   map[string]any{"hostname": "lab-r1", "platform": "Cisco IOS-XE"},
	}
	analyze := func(token string, body map[string]any) (int, []byte) {
		t.Helper()
		return do(t, srv, "POST", "/api/troubleshoot/protocol-diagnostics/analyze", token, body)
	}

	stA, bodyA := analyze(fix["A"].token, payload)
	stB, bodyB := analyze(fix["B"].token, payload)
	if stA != 200 || stB != 200 {
		t.Fatalf("analyze: A=%d B=%d, want 200/200 (%s | %s)", stA, stB, bodyA, bodyB)
	}
	if !bytes.Equal(bodyA, bodyB) {
		t.Fatalf("analyze is no longer tenant-invariant — identical requests from two orgs "+
			"produced different responses; reclassify the route \"scoped\" and add a real "+
			"cross-org isolation test.\nA: %s\nB: %s", bodyA, bodyB)
	}

	// §3a.2: a tenant smuggled into the body is rejected, never honored.
	for _, field := range []string{"tenant_id", "tenant"} {
		bad := map[string]any{"issue_id": "ospf-neighbor-stuck", field: fix["B"].tenantID}
		if st, b := analyze(fix["A"].token, bad); st != 400 {
			t.Fatalf("analyze accepted a %q field in the body: %d %s (want 400)", field, st, b)
		}
	}
}
