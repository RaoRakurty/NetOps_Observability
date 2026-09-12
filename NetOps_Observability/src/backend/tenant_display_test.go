// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// tenant_display_test.go — per-tenant display prefs (Wave 4 #11 first slice).
// Invariants: tenant keying in the store itself (§3a), default = local,
// closed enum, write gated on administration:admin with the tenant stamped
// from the PRINCIPAL (a body tenant is ignored), audited.

func displayTestServer(t *testing.T) *server {
	t.Helper()
	dir := t.TempDir()
	rs, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatal(err)
	}
	au, err := newAuditStore(dir + "/audit.json")
	if err != nil {
		t.Fatal(err)
	}
	return &server{roles: rs, audit: au, displayPrefs: newTenantDisplayStore(dir + "/display.json")}
}

func TestTenantDisplayStoreDefaultsAndKeying(t *testing.T) {
	st := newTenantDisplayStore("")
	if got := st.get("t-a").TimeDisplay; got != "local" {
		t.Fatalf("unconfigured tenant must default local, got %q", got)
	}
	_, _ = st.setTimeDisplay("t-a", "utc")
	if got := st.get("t-a").TimeDisplay; got != "utc" {
		t.Fatalf("t-a = %q, want utc", got)
	}
	// §3a: another tenant's read is keyed separately — never t-a's value.
	if got := st.get("t-b").TimeDisplay; got != "local" {
		t.Fatalf("t-b must stay default, got %q (cross-tenant bleed)", got)
	}
	var nilStore *tenantDisplayStore
	if got := nilStore.get("t-a").TimeDisplay; got != "local" {
		t.Fatalf("nil store must serve the default, got %q", got)
	}
}

func TestNormalizeTimeDisplay(t *testing.T) {
	for raw, want := range map[string]string{"local": "local", "UTC": "utc", " utc ": "utc"} {
		got, err := normalizeTimeDisplay(raw)
		if err != nil || got != want {
			t.Errorf("normalizeTimeDisplay(%q) = (%q,%v), want %q", raw, got, err, want)
		}
	}
	for _, bad := range []string{"", "browser", "PST", "local; drop"} {
		if _, err := normalizeTimeDisplay(bad); err == nil {
			t.Errorf("normalizeTimeDisplay(%q) must fail — closed enum", bad)
		}
	}
}

func TestDisplaySettingsHandlerIsolation(t *testing.T) {
	s := displayTestServer(t)
	admA := jwtClaims{Role: "admin", Tenant: "t-a", Sub: "adm-a"}
	admB := jwtClaims{Role: "admin", Tenant: "t-b", Sub: "adm-b"}
	viewerA := jwtClaims{Role: "viewer", Tenant: "t-a", Sub: "user-a"}

	put := func(c jwtClaims, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/api/settings/display", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.handleDisplaySettings(rec, claimsCtx(r, c))
		return rec
	}
	get := func(c jwtClaims) tenantDisplayConfig {
		r := httptest.NewRequest(http.MethodGet, "/api/settings/display", nil)
		rec := httptest.NewRecorder()
		s.handleDisplaySettings(rec, claimsCtx(r, c))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET = %d", rec.Code)
		}
		var cfg tenantDisplayConfig
		if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	// Tenant admin sets its OWN tenant — a tenant_id in the body is IGNORED.
	if rec := put(admA, `{"time_display":"utc","tenant_id":"t-b"}`); rec.Code != http.StatusOK {
		t.Fatalf("admin PUT = %d: %s", rec.Code, rec.Body.String())
	}
	if got := get(admA); got.TenantID != "t-a" || got.TimeDisplay != "utc" {
		t.Fatalf("t-a sees %+v, want its own utc", got)
	}
	// §3a: tenant B is untouched by A's write (and by A's body claim).
	if got := get(admB); got.TimeDisplay != "local" {
		t.Fatalf("t-b sees %q — cross-tenant write leak", got.TimeDisplay)
	}
	// A non-admin of the same tenant READS the tenant preference…
	if got := get(viewerA); got.TimeDisplay != "utc" {
		t.Fatalf("viewer of t-a sees %q, want utc", got.TimeDisplay)
	}
	// …but cannot write it.
	if rec := put(viewerA, `{"time_display":"local"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer PUT = %d, want 403", rec.Code)
	}
	// Closed enum → 400, never a silent default.
	if rec := put(admA, `{"time_display":"browser"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad enum PUT = %d, want 400", rec.Code)
	}
	// Unauthenticated GET → 401.
	r := httptest.NewRequest(http.MethodGet, "/api/settings/display", nil)
	rec := httptest.NewRecorder()
	s.handleDisplaySettings(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon GET = %d, want 401", rec.Code)
	}
	// The write is audited.
	events := auditList(t, s, "t-a", false, auditQuery{})
	found := false
	for _, e := range events {
		if e.Detail["action"] == "set_time_display" {
			found = true
		}
	}
	if !found {
		t.Fatal("time-display change must be audited")
	}
}
