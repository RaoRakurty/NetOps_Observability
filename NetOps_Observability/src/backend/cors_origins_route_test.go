// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cors_origins_route_test.go — the Cross-origin access setting (tracker 439)
// through the REAL router + auth middleware, and the CORS middleware reading it
// LIVE. §3a rule 3: the list is platform-GLOBAL plumbing, so the gate is
// requirePlatformAdmin; a tenant admin and an org admin each hold full
// administration rights inside their scope and must still be refused.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/corsallow"
	"netops/backend/internal/platformdb"
)

func newCORSFixture(t *testing.T, env string) *featureFixture {
	t.Helper()
	f := newFeatureFixture(t)
	key := t.TempDir() + "/cors_allowed_origins.json"
	f.s.corsAllow = corsallow.New(corsallow.KVStore{Key: key, LoadFn: platformdb.Load, SaveFn: platformdb.Save}, env)
	if err := f.s.corsAllow.Load(); err != nil {
		t.Fatal(err)
	}
	return f
}

const corsRoute = "/api/platform/cors-origins"

func TestCORSOriginsSettingIsPlatformAdminOnly(t *testing.T) {
	f := newCORSFixture(t, "")
	if st, b := f.call("POST", "/api/orgs", f.admin, map[string]any{"name": "Acme Corp"}); st != 201 {
		t.Fatalf("create org: %d %s", st, b)
	}
	if st, _ := f.call("POST", "/api/tenants", f.admin, map[string]any{"name": "Acme Prod", "org_id": "acme-corp"}); st != 201 {
		t.Fatal("create tenant")
	}
	for _, u := range []map[string]any{
		{"username": "orgboss", "password": "Passw0rd!2345", "role": "org-admin", "tenant_id": "acme-prod"},
		{"username": "tadmin", "password": "Passw0rd!2345", "role": "super-admin", "tenant_id": "acme-prod"},
	} {
		if st, _ := f.call("POST", "/api/users", f.admin, u); st != 201 {
			t.Fatal("create user")
		}
	}
	body := map[string]any{"origins": []string{"https://shop.acme.example"}}
	for _, m := range []string{"GET", "PUT"} {
		if st, _ := f.call(m, corsRoute, "", body); st != 401 {
			t.Errorf("unauthenticated %s = %d, want 401", m, st)
		}
	}
	for _, who := range []string{"orgboss", "tadmin"} {
		tok := login(t, f.ts, who, "Passw0rd!2345").Token
		if st, _ := f.call("GET", corsRoute, tok, nil); st != 403 {
			t.Errorf("%s GET = %d, want 403", who, st)
		}
		if st, _ := f.call("GET", corsRoute+"?as_tenant=acme-prod", tok, nil); st != 403 {
			t.Errorf("%s as_tenant GET = %d, want 403", who, st)
		}
		if st, _ := f.call("PUT", corsRoute, tok, body); st != 403 {
			t.Errorf("%s PUT = %d, want 403", who, st)
		}
	}
	if f.s.corsAllowed("https://shop.acme.example") {
		t.Fatal("a refused caller changed the cross-origin allowlist")
	}

	// The platform administrator: a wildcard is refused, a real origin saved.
	if st, b := f.call("PUT", corsRoute, f.admin, map[string]any{"origins": []string{"*"}}); st != 400 {
		t.Fatalf("PUT * = %d %s, want 400", st, b)
	}
	st, b := f.call("PUT", corsRoute, f.admin, body)
	if st != 200 {
		t.Fatalf("platform admin PUT = %d %s", st, b)
	}
	st, b = f.call("GET", corsRoute, f.admin, nil)
	var v corsallow.View
	if st != 200 || json.Unmarshal(b, &v) != nil || v.Source != corsallow.SourceSaved || len(v.Origins) != 1 {
		t.Fatalf("platform admin GET = %d %s", st, b)
	}

	// Audited once, as a platform (cross-tenant) action, with old → new.
	evs, err := f.s.audit.List("", true, auditQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, e := range evs {
		if e.Detail["action"] == "cors_origins_set" && e.Status == 200 {
			found++
			if !strings.Contains(stringify(e.Detail["to"]), "https://shop.acme.example") {
				t.Errorf("audit 'to' = %v", e.Detail["to"])
			}
		}
	}
	if found != 1 {
		t.Fatalf("audit rows = %d, want 1", found)
	}
}

func stringify(v any) string { b, _ := json.Marshal(v); return string(b) }

// The CORS middleware reads the list on every request: a saved change applies
// to the very next preflight, with no restart.
func TestCORSMiddlewareReadsTheSettingLive(t *testing.T) {
	f := newCORSFixture(t, "https://env.example.com")
	h := withCORS(f.s.corsAllowed, f.ts.Config.Handler)

	preflight := func(origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodOptions, "/api/dem/events", nil)
		r.Header.Set("Origin", origin)
		r.Header.Set("Access-Control-Request-Method", "POST")
		r.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	acao := func(w *httptest.ResponseRecorder) string { return w.Header().Get("Access-Control-Allow-Origin") }

	// Install value in force.
	if w := preflight("https://env.example.com"); w.Code != http.StatusNoContent || acao(w) != "https://env.example.com" ||
		!strings.Contains(w.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("install-value preflight = %d %v", w.Code, w.Header())
	}
	if w := preflight("https://rum.example.com"); acao(w) != "" {
		t.Fatal("an origin not on the list must get no CORS headers")
	}

	// Save a new list: the next preflight follows it.
	if st, b := f.call("PUT", corsRoute, f.admin, map[string]any{"origins": []string{"https://rum.example.com"}}); st != 200 {
		t.Fatalf("PUT = %d %s", st, b)
	}
	if w := preflight("https://rum.example.com"); acao(w) != "https://rum.example.com" || w.Header().Get("Vary") != "Origin" {
		t.Fatalf("saved-origin preflight headers = %v", w.Header())
	}
	if w := preflight("https://env.example.com"); acao(w) != "" {
		t.Fatal("the saved list replaces the install value")
	}
	// Never a wildcard, never a reflected stranger.
	for _, o := range []string{"*", "null", "https://evil.example.com", "https://rum.example.com.evil.com"} {
		if w := preflight(o); acao(w) != "" {
			t.Errorf("origin %q got ACAO %q", o, acao(w))
		}
	}
	// The WebSocket origin check reads the same live list.
	r := httptest.NewRequest(http.MethodGet, "http://api.local/api/events", nil)
	r.Host = "api.local"
	r.Header.Set("Origin", "https://rum.example.com")
	if !f.s.wsOriginAllowed(r) {
		t.Fatal("the WebSocket origin check must follow the saved list")
	}
	// Reset: the install value is back.
	if st, b := f.call("PUT", corsRoute, f.admin, map[string]any{"reset": true}); st != 200 {
		t.Fatalf("reset = %d %s", st, b)
	}
	if w := preflight("https://env.example.com"); acao(w) != "https://env.example.com" {
		t.Fatal("reset must restore the install value")
	}
}
