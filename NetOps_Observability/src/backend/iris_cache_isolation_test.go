// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_cache_isolation_test.go — the Iris per-tenant caches (tracker 337
// N-H4) under §3a: a warm cache for one tenant never answers another, a write
// is visible to its own tenant at once (the cross view too) and leaves other
// tenants' entries alone, a delete invalidates, an as_tenant walk by a
// non-owner is ignored — for the alias cache and the Network context cache.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

func cachedAliasFixture(t *testing.T) (*server, jwtClaims, jwtClaims) {
	t.Helper()
	s, a, b := aliasFixture(t)
	s.irisAliasCache = newIrisAliasCache()
	s.nlqAliases.OnWrite = s.irisAliasesChanged
	return s, a, b
}

func aliasTargets(t *testing.T, s *server, c jwtClaims) []string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	got, err := newNLQLookups(s, r, c).Aliases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, a := range got {
		out = append(out, a.Alias+"→"+a.EntityID)
	}
	sort.Strings(out)
	return out
}

func TestIrisAliasCacheIsTenantIsolated(t *testing.T) {
	s, a, b := cachedAliasFixture(t)
	// The same words in two tenants mean two different things.
	if code, body := aliasCall(t, s, a, http.MethodPut, "/api/ai/aliases", `{"entity_type":"site","entity_id":"site:dfw-hq","alias":"DFW"}`); code != 200 {
		t.Fatalf("A put: %d %s", code, body)
	}
	if code, body := aliasCall(t, s, b, http.MethodPut, "/api/ai/aliases", `{"entity_type":"site","entity_id":"site:dfw-hq","alias":"Big D"}`); code != 200 {
		t.Fatalf("B put: %d %s", code, body)
	}
	for i := 0; i < 3; i++ { // warm, then read from the cache
		if got := strings.Join(aliasTargets(t, s, a), ","); got != "DFW→site:dfw-hq" {
			t.Fatalf("A read %q", got)
		}
		if got := strings.Join(aliasTargets(t, s, b), ","); got != "Big D→site:dfw-hq" {
			t.Fatalf("CROSS-TENANT LEAK through the cache: B read %q", got)
		}
	}
	if st := s.irisAliasCache.Stats(); st.Hits < 4 {
		t.Fatalf("the reads should have come from the cache: %+v", st)
	}

	// An as_tenant walk by a non-owner is ignored: still B's own view.
	walker := b
	walker.ActingTenant = a.Tenant
	if got := strings.Join(aliasTargets(t, s, walker), ","); got != "Big D→site:dfw-hq" {
		t.Fatalf("an as_tenant walk reached A's cached aliases: %q", got)
	}

	// The platform owner's Global view holds both.
	owner := jwtClaims{Sub: "owner", Role: "admin", Tenant: TenantGlobal}
	if got := aliasTargets(t, s, owner); len(got) != 2 {
		t.Fatalf("the Global view should see both tenants' aliases: %v", got)
	}

	// A's write is visible to A at once and refreshes the Global view; B's
	// entry is untouched (still served from the cache).
	hitsBefore := s.irisAliasCache.Stats().Hits
	if code, body := aliasCall(t, s, a, http.MethodPut, "/api/ai/aliases", `{"entity_type":"site","entity_id":"site:dfw-hq","alias":"HQ"}`); code != 200 {
		t.Fatalf("A second put: %d %s", code, body)
	}
	if got := strings.Join(aliasTargets(t, s, a), ","); got != "DFW→site:dfw-hq,HQ→site:dfw-hq" {
		t.Fatalf("A's own write is not visible to A: %q", got)
	}
	if got := aliasTargets(t, s, owner); len(got) != 3 {
		t.Fatalf("the Global view is stale after A's write: %v", got)
	}
	aliasTargets(t, s, b)
	if s.irisAliasCache.Stats().Hits <= hitsBefore {
		t.Fatal("B's entry should have survived A's write")
	}

	// A delete invalidates.
	if code, body := aliasCall(t, s, a, http.MethodDelete, "/api/ai/aliases?entity_type=site&alias=DFW", ""); code != 200 && code != 204 {
		t.Fatalf("delete: %d %s", code, body)
	}
	if got := strings.Join(aliasTargets(t, s, a), ","); got != "HQ→site:dfw-hq" {
		t.Fatalf("a deleted alias is still served: %q", got)
	}
}

// The Network context block is cached per tenant and invalidated by approve,
// rollback and retire; another tenant never receives a cached block.
func TestIrisContextCacheIsTenantIsolatedAndInvalidated(t *testing.T) {
	s, h, alice, bob, reviewer := ctxFixture(t)
	s.irisContextCache = newIrisContextCache()
	if blk := s.orgContextBlock(context.Background(), alice); blk != "" {
		t.Fatal("nothing approved yet")
	}
	id, sha := newFact(t, h, alice, "core-02 is the DR site")
	serveAs(h, alice, http.MethodPost, "/api/ai/context/"+id+"/submit", "")
	if code := approve(h, reviewer, id, sha); code != http.StatusOK {
		t.Fatalf("approve: %d", code)
	}
	// Approval invalidated A's cached empty block.
	if blk := s.orgContextBlock(context.Background(), alice); !strings.Contains(blk, "core-02") {
		t.Fatalf("an approved fact is not visible at once: %q", blk)
	}
	if blk := s.orgContextBlock(context.Background(), bob); blk != "" {
		t.Fatalf("CROSS-TENANT LEAK through the cache: B received %q", blk)
	}
	if st := s.irisContextCache.Stats(); st.Entries != 2 {
		t.Fatalf("one entry per tenant expected: %+v", st)
	}
	if code, _ := ctxCall(t, h, reviewer, http.MethodPost, "/api/ai/context/"+id+"/retire", `{"reason":"gone"}`); code != http.StatusOK {
		t.Fatalf("retire: %d", code)
	}
	if blk := s.orgContextBlock(context.Background(), alice); blk != "" {
		t.Fatalf("a retired fact is still served from the cache: %q", blk)
	}
}
