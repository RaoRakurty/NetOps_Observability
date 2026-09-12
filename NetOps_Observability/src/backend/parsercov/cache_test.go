// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package parsercov

// cache_test.go — the bound is an ASSERTION, not a hope.
//
// An unbounded cache keyed on caller-derived values is a memory hole any
// authenticated principal can walk, so the size ceiling, the TTL and the
// eviction order are all pinned here.

import (
	"fmt"
	"testing"
	"time"
)

func runFor(id string) runResult {
	return runResult{
		Days: 7,
		Lane: LaneSyslog,
		All:  []Item{{TemplateID: id, Template: "shape " + id, Count: 1}},
	}
}

func TestCacheSizeIsBounded(t *testing.T) {
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	c := newMiningCache(func() time.Time { return now })
	for i := 0; i < maxCacheEntries*4; i++ {
		c.put(fmt.Sprintf("key-%d", i), runFor(fmt.Sprintf("t-%010d", i)))
		if got := c.size(); got > maxCacheEntries {
			t.Fatalf("cache grew to %d entries, bound is %d", got, maxCacheEntries)
		}
	}
	if got := c.size(); got != maxCacheEntries {
		t.Fatalf("cache settled at %d entries, want the full %d", got, maxCacheEntries)
	}
	// Oldest-first eviction: the first key written is long gone, the last is
	// still there.
	if c.get("key-0") != nil {
		t.Fatal("key-0 survived 256 insertions — eviction is not oldest-first")
	}
	last := fmt.Sprintf("key-%d", maxCacheEntries*4-1)
	if c.get(last) == nil {
		t.Fatalf("%s was evicted although it is the newest entry", last)
	}
}

func TestCacheExpiresOnRead(t *testing.T) {
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	c := newMiningCache(clock)
	c.put("k", runFor("t-0000000001"))
	if c.get("k") == nil {
		t.Fatal("a freshly stored entry must be readable")
	}
	now = now.Add(cacheTTL - time.Second)
	if c.get("k") == nil {
		t.Fatal("an entry just inside the TTL must still be readable")
	}
	now = now.Add(2 * time.Second) // now past the TTL
	if c.get("k") != nil {
		t.Fatal("an expired entry was served — a stale mining result must never be returned")
	}
	if c.size() != 0 {
		t.Fatalf("the expired entry was not dropped on read: size=%d", c.size())
	}
}

func TestCacheSweepsExpiredEntriesOnWrite(t *testing.T) {
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	c := newMiningCache(clock)
	for i := 0; i < 10; i++ {
		c.put(fmt.Sprintf("old-%d", i), runFor(fmt.Sprintf("t-%010d", i)))
	}
	now = now.Add(cacheTTL + time.Minute)
	c.put("fresh", runFor("t-9999999999"))
	if got := c.size(); got != 1 {
		t.Fatalf("expired entries were not swept on write: size=%d, want 1", got)
	}
	if c.get("fresh") == nil {
		t.Fatal("the entry written during the sweep was itself swept")
	}
}

func TestCacheOverwriteDoesNotDuplicateOrderSlot(t *testing.T) {
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	c := newMiningCache(func() time.Time { return now })
	for i := 0; i < 5; i++ {
		c.put("same", runFor(fmt.Sprintf("t-%010d", i)))
	}
	if got := c.size(); got != 1 {
		t.Fatalf("re-writing one key produced %d entries", got)
	}
	if got := len(c.order); got != 1 {
		t.Fatalf("re-writing one key left %d order slots", got)
	}
	e := c.get("same")
	if e == nil || e.run.All[0].TemplateID != "t-0000000004" {
		t.Fatalf("the last write did not win: %+v", e)
	}
}

// TestCacheKeyIsScopeSensitive is an ISOLATION test, not a caching one: two
// principals whose resolved scopes differ must never collide on one entry, or
// one tenant would be served the other's mined shapes out of memory.
func TestCacheKeyIsScopeSensitive(t *testing.T) {
	base := cacheKey("netops-syslog-acme-*", []byte(`{"term":{"tenant_id":"acme"}}`), 7, LaneSyslog)
	variants := map[string]string{
		"different index":   cacheKey("netops-syslog-globex-*", []byte(`{"term":{"tenant_id":"acme"}}`), 7, LaneSyslog),
		"different clause":  cacheKey("netops-syslog-acme-*", []byte(`{"term":{"tenant_id":"globex"}}`), 7, LaneSyslog),
		"different window":  cacheKey("netops-syslog-acme-*", []byte(`{"term":{"tenant_id":"acme"}}`), 14, LaneSyslog),
		"different lane":    cacheKey("netops-syslog-acme-*", []byte(`{"term":{"tenant_id":"acme"}}`), 7, LaneTrap),
		"empty clause vs a": cacheKey("netops-syslog-acme-*", nil, 7, LaneSyslog),
	}
	for name, k := range variants {
		if k == base {
			t.Errorf("%s produced the SAME cache key — scopes would share a mining result", name)
		}
	}
	if again := cacheKey("netops-syslog-acme-*", []byte(`{"term":{"tenant_id":"acme"}}`), 7, LaneSyslog); again != base {
		t.Fatal("cacheKey is not deterministic")
	}
}
