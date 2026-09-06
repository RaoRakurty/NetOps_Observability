// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// platform_config_authz_test.go — platform-GLOBAL config (auth providers, LLM
// key, token policy, notification channels) is single-instance "platform
// plumbing": only the PLATFORM OWNER may read/mutate it. A tenant/org admin holds
// administration:admin within its own scope but must NOT reach platform plumbing
// (the org-admin role grid is full-admin; the SCOPE is the limiter). This guards
// the requireAdmin→requirePlatformAdmin fix from regressing.

import "testing"

func TestPlatformGlobalConfigIsOwnerOnly(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token // platform owner

	// Build an org + tenant + an org-admin and a tenant super-admin inside it.
	st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Acme Corp"})
	if st != 201 {
		t.Fatalf("create org: %d %s", st, b)
	}
	if st, _ := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Acme Prod", "org_id": "acme-corp"}); st != 201 {
		t.Fatal("create tenant")
	}
	if st, _ := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "orgboss", "password": "Passw0rd!2345", "role": "org-admin", "tenant_id": "acme-prod",
	}); st != 201 {
		t.Fatal("create org-admin")
	}
	if st, _ := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "tadmin", "password": "Passw0rd!2345", "role": "super-admin", "tenant_id": "acme-prod",
	}); st != 201 {
		t.Fatal("create tenant super-admin")
	}
	orgBoss := login(t, srv, "orgboss", "Passw0rd!2345").Token
	tenantAdmin := login(t, srv, "tadmin", "Passw0rd!2345").Token

	// Every platform-global config endpoint: GET and PUT.
	endpoints := []string{
		"/api/auth/ldap/config",
		"/api/auth/tacacs/config",
		"/api/auth/oidc/config",
		"/api/auth/token-policy",
		"/api/copilot/config",
		"/api/notify/smtp",
		"/api/notify/slack",
	}
	for _, ep := range endpoints {
		for _, who := range []struct {
			name, token string
		}{{"org-admin", orgBoss}, {"tenant-admin", tenantAdmin}} {
			// READ must be denied (403), not leak platform config.
			if st, _ := do(t, srv, "GET", ep, who.token, nil); st != 403 {
				t.Errorf("%s GET %s = %d, want 403 (platform-owner only)", who.name, ep, st)
			}
			// MUTATE must be denied (403) — the real escalation risk.
			if st, _ := do(t, srv, "PUT", ep, who.token, map[string]any{"enabled": true}); st != 403 {
				t.Errorf("%s PUT %s = %d, want 403 (platform-owner only)", who.name, ep, st)
			}
		}
	}
	// (We don't exercise the platform-owner ALLOW path here: the shared test
	// harness doesn't wire the LDAP/TACACS/OIDC/copilot/notify/token stores, so the
	// owner would pass the gate and then hit a nil store. The gate itself — the
	// security boundary — is fully asserted above via the non-owner 403s.)
	_ = admin
}
