// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_alias_test.go — the alias API and resolution endpoint (tracker 337
// N-C2), §3a end to end: own-only list, a foreign alias deletes as 404, a
// smuggled tenant field is refused, an alias may only point at an entity the
// caller can see, a Global view cannot write, and resolution never crosses
// tenants — tenant B saying "DFW" resolves nothing of tenant A's.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/entityalias"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/resolve"
)

type memAliasColl struct{ m map[string]entityalias.Alias }

func (c *memAliasColl) All(t string, cross bool) []entityalias.Alias {
	var out []entityalias.Alias
	for _, a := range c.m {
		if cross || a.TenantID == t {
			out = append(out, a)
		}
	}
	return out
}
func (c *memAliasColl) Get(t string, cross bool, id string) (entityalias.Alias, bool) {
	a, ok := c.m[t+"\x00"+id]
	return a, ok
}
func (c *memAliasColl) Upsert(a entityalias.Alias) error {
	c.m[a.TenantID+"\x00"+a.Key()] = a
	return nil
}
func (c *memAliasColl) Delete(t string, _ bool, id string) bool {
	if _, ok := c.m[t+"\x00"+id]; !ok {
		return false
	}
	delete(c.m, t+"\x00"+id)
	return true
}

func aliasFixture(t *testing.T) (*server, jwtClaims, jwtClaims) {
	t.Helper()
	s, a, b := nlqFixture(t) // dev-a (t-a) and dev-b (t-b), both labelled site dfw-hq
	cat := catalog.MustLoad()
	s.nlqCatalog = cat
	s.nlqAliases = &entityalias.Store{C: &memAliasColl{m: map[string]entityalias.Alias{}}, Cat: cat}
	sites, err := newSitesStore(t.TempDir() + "/sites.json")
	if err != nil {
		t.Fatal(err)
	}
	s.sites = sites
	for _, st := range []Site{{TenantID: "t-a", Slug: "dfw-hq", Name: "Dallas HQ"}, {TenantID: "t-b", Slug: "dfw-hq", Name: "Dallas HQ"}} {
		if _, err := s.sites.Upsert(st); err != nil {
			t.Fatal(err)
		}
	}
	a.Role, b.Role = "admin", "admin"
	return s, a, b
}

func aliasCall(t *testing.T, s *server, c jwtClaims, method, target, body string) (int, string) {
	t.Helper()
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	if strings.HasPrefix(target, "/api/ai/entities/resolve") {
		s.handleAIEntityResolve(w, r)
	} else {
		s.handleAIAliases(w, r)
	}
	return w.Code, w.Body.String()
}

func TestAliasAPIIsTenantIsolated(t *testing.T) {
	s, a, b := aliasFixture(t)
	if code, body := aliasCall(t, s, a, http.MethodPut, "/api/ai/aliases", `{"entity_type":"site","entity_id":"site:dfw-hq","alias":"DFW"}`); code != 200 {
		t.Fatalf("tenant A put: %d %s", code, body)
	}
	_, body := aliasCall(t, s, b, http.MethodGet, "/api/ai/aliases", "")
	if strings.Contains(body, "DFW") {
		t.Fatalf("tenant B listed tenant A's alias: %s", body)
	}
	if code, _ := aliasCall(t, s, b, http.MethodDelete, "/api/ai/aliases?entity_type=site&alias=DFW", ""); code != http.StatusNotFound {
		t.Fatalf("tenant B deleting tenant A's alias = %d, want 404", code)
	}
	_, body = aliasCall(t, s, a, http.MethodGet, "/api/ai/aliases", "")
	if !strings.Contains(body, `"alias":"DFW"`) {
		t.Fatalf("tenant A's alias must survive B's delete attempt: %s", body)
	}
}

func TestAliasAPIRefuses(t *testing.T) {
	s, a, _ := aliasFixture(t)
	cases := map[string]struct {
		claims jwtClaims
		body   string
		code   int
	}{
		"smuggled tenant":   {a, `{"entity_type":"site","entity_id":"site:dfw-hq","alias":"X","tenant_id":"t-b"}`, http.StatusBadRequest},
		"foreign device":    {a, `{"entity_type":"device","entity_id":"device:dev-b","alias":"their box"}`, http.StatusNotFound},
		"unknown site":      {a, `{"entity_type":"site","entity_id":"site:nowhere","alias":"nowhere"}`, http.StatusNotFound},
		"bad id form":       {a, `{"entity_type":"site","entity_id":"device:dev-a","alias":"x"}`, http.StatusBadRequest},
		"global view write": {jwtClaims{Sub: "owner", Role: "super-admin"}, `{"entity_type":"provider","entity_id":"provider:comcast","alias":"CMCSA"}`, http.StatusBadRequest},
	}
	for name, c := range cases {
		if code, body := aliasCall(t, s, c.claims, http.MethodPut, "/api/ai/aliases", c.body); code != c.code {
			t.Errorf("%s: got %d %s, want %d", name, code, body, c.code)
		}
	}
	// A provider is a tenant-scoped name the alias defines — no visibility check.
	if code, body := aliasCall(t, s, a, http.MethodPut, "/api/ai/aliases", `{"entity_type":"provider","entity_id":"provider:comcast","alias":"Comcast"}`); code != 200 {
		t.Fatalf("provider alias: %d %s", code, body)
	}
}

func TestResolveNeverCrossesTenants(t *testing.T) {
	s, a, b := aliasFixture(t)
	if code, body := aliasCall(t, s, a, http.MethodPut, "/api/ai/aliases", `{"entity_type":"site","entity_id":"site:dfw-hq","alias":"Big D"}`); code != 200 {
		t.Fatalf("put: %d %s", code, body)
	}
	decode := func(body string) resolve.Result {
		var r resolve.Result
		if err := json.Unmarshal([]byte(body), &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	_, body := aliasCall(t, s, a, http.MethodPost, "/api/ai/entities/resolve", `{"text":"big d"}`)
	if r := decode(body); len(r.Refs) != 1 || r.Refs[0].EntityID != "site:dfw-hq" || r.Refs[0].Method != resolve.MethodTenantAlias {
		t.Fatalf("tenant A resolve = %s", body)
	}
	_, body = aliasCall(t, s, b, http.MethodPost, "/api/ai/entities/resolve", `{"text":"big d"}`)
	if r := decode(body); len(r.Refs) != 0 {
		t.Fatalf("tenant B resolved tenant A's alias: %s", body)
	}
	// Inventory names resolve only within the caller's own devices.
	_, body = aliasCall(t, s, b, http.MethodPost, "/api/ai/entities/resolve", `{"text":"edge-a","types":["device"]}`)
	if r := decode(body); len(r.Refs) != 0 {
		t.Fatalf("tenant B resolved tenant A's device name: %s", body)
	}
	if code, _ := aliasCall(t, s, a, http.MethodPost, "/api/ai/entities/resolve", `{"text":"x","types":["planet"]}`); code != http.StatusBadRequest {
		t.Fatal("an unknown entity type must be refused")
	}
}

func TestNLRoutesAre503WithoutACatalog(t *testing.T) {
	s, a, _ := nlqFixture(t)
	s.nlqCatalog = nil
	if code, _ := aliasCall(t, s, a, http.MethodGet, "/api/ai/aliases", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("got %d", code)
	}
}
