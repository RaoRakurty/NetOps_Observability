package backend

import (
	"encoding/json"
	"netops/backend/nms"
	"strings"
	"testing"
)

// nms_isolation_test.go — §3a cross-org isolation for the NMS integration
// surface (#95), exercised through the REAL router + auth middleware the way
// the running system behaves. Two orgs, each with one tenant + one tenant-
// scoped operator: each sees ONLY its own integrations, cross-tenant access by
// id is 404 (never existence-revealing), credential VALUES never appear in any
// response, and the platform owner sees all.
func TestNMSCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	// The harness doesn't wire the NMS runtime (feature-flagged in main); the
	// handlers read it at request time, so setting it on the live *server is
	// enough. Mem store = the same in-store tenant scoping contract as PG-RLS.
	s.nms = newNMSRuntime(nms.NewMemStore())

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	type fixture struct {
		tenantID, token, intID string
	}
	fix := map[string]*fixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "nms-user-" + name
		if st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		}); st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &fixture{tenantID: tenantID, token: login(t, srv, user, "Passw0rd!2345").Token}
	}

	const secretValue = "hunter2-very-secret"

	// Each tenant user creates one integration with credentials.
	for _, name := range []string{"A", "B"} {
		f := fix[name]
		st, b := do(t, srv, "POST", "/api/nms/integrations", f.token, map[string]any{
			"vendor":      "generic",
			"displayName": "Controller " + name,
			"baseUrl":     "https://controller-" + name + ".example",
			"credentials": map[string]string{"username": "ro", "password": secretValue, "webhook_secret": secretValue},
		})
		if st != 201 {
			t.Fatalf("user %s create integration: %d %s", name, st, b)
		}
		if strings.Contains(string(b), secretValue) {
			t.Fatalf("credential VALUE leaked in create response: %s", b)
		}
		f.intID = idOf(t, b)
	}

	a, b := fix["A"], fix["B"]

	list := func(token, asTenant string) []string {
		path := "/api/nms/integrations"
		if asTenant != "" {
			path += "?as_tenant=" + asTenant
		}
		st, body := do(t, srv, "GET", path, token, nil)
		if st != 200 {
			t.Fatalf("GET %s: %d %s", path, st, body)
		}
		if strings.Contains(string(body), secretValue) {
			t.Fatalf("credential VALUE leaked in list response: %s", body)
		}
		var r struct {
			Integrations []struct {
				ID string `json:"id"`
			} `json:"integrations"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			t.Fatalf("decode: %v (%s)", err, body)
		}
		out := make([]string, 0, len(r.Integrations))
		for _, c := range r.Integrations {
			out = append(out, c.ID)
		}
		return out
	}

	// 1) Own-only list for each tenant user.
	if got := list(a.token, ""); len(got) != 1 || got[0] != a.intID {
		t.Fatalf("org A list leak: %v, want exactly [%s]", got, a.intID)
	}
	if got := list(b.token, ""); len(got) != 1 || got[0] != b.intID {
		t.Fatalf("org B list leak: %v, want exactly [%s]", got, b.intID)
	}

	// 2) Platform owner sees both.
	if got := list(admin, ""); len(got) != 2 {
		t.Fatalf("platform owner sees %v, want 2", got)
	}

	// 3) Cross-tenant GET by id → 404 (existence never revealed), incl. health.
	if st, _ := do(t, srv, "GET", "/api/nms/integrations/"+b.intID, a.token, nil); st != 404 {
		t.Fatalf("user-A GET org-B integration: %d, want 404", st)
	}
	if st, _ := do(t, srv, "GET", "/api/nms/integrations/"+b.intID+"/health", a.token, nil); st != 404 {
		t.Fatalf("user-A GET org-B health: %d, want 404", st)
	}

	// 4) Cross-tenant PUT/DELETE → 404, and B's row survives untouched.
	if st, _ := do(t, srv, "PUT", "/api/nms/integrations/"+b.intID, a.token,
		map[string]any{"displayName": "PWNED"}); st != 404 {
		t.Fatalf("user-A PUT org-B integration: %d, want 404", st)
	}
	if st, _ := do(t, srv, "DELETE", "/api/nms/integrations/"+b.intID, a.token, nil); st != 404 {
		t.Fatalf("user-A DELETE org-B integration: %d, want 404", st)
	}
	if got := list(b.token, ""); len(got) != 1 || got[0] != b.intID {
		t.Fatalf("org-B integration affected by A's delete: %v", got)
	}

	// 5) as_tenant into another org's tenant is ignored (no binding).
	if got := list(a.token, b.tenantID); len(got) != 1 || got[0] != a.intID {
		t.Fatalf("user-A ?as_tenant=%s leaked: %v", b.tenantID, got)
	}

	// 6) GET own integration: credential NAMES only, never values; webhook URL
	//    present (generic connector supports webhooks) but token differs per row.
	st, body := do(t, srv, "GET", "/api/nms/integrations/"+a.intID, a.token, nil)
	if st != 200 {
		t.Fatalf("GET own integration: %d %s", st, body)
	}
	if strings.Contains(string(body), secretValue) {
		t.Fatalf("credential VALUE leaked: %s", body)
	}
	var got struct {
		CredentialFieldsSet []string `json:"credentialFieldsSet"`
		WebhookURL          string   `json:"webhookUrl"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.CredentialFieldsSet) != 3 {
		t.Fatalf("want 3 credential field names, got %v", got.CredentialFieldsSet)
	}
	if got.WebhookURL == "" {
		t.Fatal("generic integration should carry a webhook URL")
	}

	// 7) Dormant surface: with the runtime nil the routes don't exist (404),
	//    even for the platform owner.
	s.nms = nil
	if st, _ := do(t, srv, "GET", "/api/nms/integrations", admin, nil); st != 404 {
		t.Fatalf("dormant NMS surface should 404, got %d", st)
	}
}
