// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// credentials_gate_test.go — GET /api/credentials reports the PLATFORM-GLOBAL
// integration posture (which provider credentials and feature flags the stack was
// started with). It used to discard the request entirely — no authorization was
// even possible — so every authenticated caller learned the platform's
// integration inventory. Per CLAUDE.md §3a rule 3 that is platform-owner surface:
// a tenant/org admin holds administration:admin, so a scope-blind requireAdmin
// would still be a privilege leak. These tests pin the gate.

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestCredentialsRequiresPlatformAdmin(t *testing.T) {
	srv, s := newTestServerState(t)
	// The shared harness doesn't wire the notification config store; the handler
	// reads it at request time, so setting it on the live *server is enough.
	s.notifyCfg = newNotifyConfigStore(filepath.Join(t.TempDir(), "notify.json"), s)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// A tenant with an ORG-ADMIN (full administration:admin) and an operator.
	st, b := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Creds Tenant"})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenantID := idOf(t, b)
	for _, u := range []struct{ name, role string }{
		{"creds-tenant-admin", RoleOrgAdmin},
		{"creds-operator", RoleOperator},
	} {
		if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": u.name, "password": "Passw0rd!2345", "role": u.role, "tenant_id": tenantID,
		}); st != 201 {
			t.Fatalf("create user %s: %d %s", u.name, st, b)
		}
		token := login(t, srv, u.name, "Passw0rd!2345").Token
		if st, b := do(t, srv, "GET", "/api/credentials", token, nil); st != 403 {
			t.Errorf("%s (%s) GET /api/credentials: status %d, want 403 (%s)", u.name, u.role, st, b)
		}
	}

	// An unauthenticated caller never reaches the handler at all.
	if st, _ := do(t, srv, "GET", "/api/credentials", "", nil); st != 401 {
		t.Errorf("anonymous GET /api/credentials: status %d, want 401", st)
	}

	// The platform owner still gets the full, unchanged response shape.
	st, b = do(t, srv, "GET", "/api/credentials", admin, nil)
	if st != 200 {
		t.Fatalf("platform owner GET /api/credentials: status %d, want 200 (%s)", st, b)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("decode credentials: %v (%s)", err, b)
	}
	for _, key := range []string{
		"netbox", "slack", "pagerduty", "smtp", "twilio", "aws_sns", "opensearch",
		"clickhouse", "copilot", "device_ssh", "active_verification",
	} {
		v, ok := got[key]
		if !ok {
			t.Errorf("response shape changed: missing key %q in %s", key, b)
			continue
		}
		if _, isBool := v.(bool); !isBool {
			t.Errorf("key %q must stay a presence boolean, got %T", key, v)
		}
	}
	// Presence flags only — never the secret itself.
	if len(got) != 11 {
		t.Errorf("unexpected credential keys (%d) — review for secret leakage: %s", len(got), b)
	}
}
