// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package iriscache holds Iris's per-tenant read caches (tracker 337 N-H4):
// small, hot, tenant-owned data an answer reads on every question — the
// workspace's entity aliases, its approved Network context.
//
// TENANT IDENTITY IS THE KEY. A Key is a struct of exactly the inputs the
// uncached read takes — (tenant, cross, scope) as principalTenant returns them
// — never a joined string, so two different callers cannot collide on one
// entry. A non-cross caller with no tenant is never cached (default-closed).
//
// CORRECTNESS IS INVALIDATION; TTL ONLY BOUNDS STALENESS. Every writer calls
// InvalidateTenant(t) after its write commits. That drops t's entries AND
// every cross-tenant entry (a Global view contains t's rows). A per-tenant
// generation counter stops a read that began before an invalidation from
// storing what it read. The TTL caps how stale an entry can be if a write
// arrives from somewhere this process does not see (another replica).
//
// Errors are never cached. Every value is handed out as a CLONE, so a caller
// that sorts or appends cannot change what the next caller reads. Entries are
// bounded; the oldest is evicted first.
//
// Stdlib only.
package iriscache

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Key is one cached read's inputs.
type Key struct {
	Tenant string
	Cross  bool
	Scope  string
}

type entry[V any] struct {
	v   V
	at  time.Time
	seq uint64 // insertion order, for eviction
}

// Cache is one named, bounded, TTL'd, tenant-keyed cache.
type Cache[V any] struct {
	name  string
	ttl   time.Duration
	max   int
	clone func(V) V
	now   func() time.Time

	mu       sync.Mutex
	entries  map[Key]entry[V]
	gen      map[string]uint64 // tenant → generation
	crossGen uint64            // bumped by every tenant invalidation
	allGen   uint64            // bumped by InvalidateAll
	seq      uint64

	hits, misses, expired, invalidations atomic.Int64
}

// New builds a cache. clone copies a value (nil = values are immutable).
func New[V any](name string, ttl time.Duration, max int, clone func(V) V) *Cache[V] {
	if max <= 0 {
		max = 1024
	}
	if clone == nil {
		clone = func(v V) V { return v }
	}
	return &Cache[V]{name: name, ttl: ttl, max: max, clone: clone, now: time.Now,
		entries: map[Key]entry[V]{}, gen: map[string]uint64{}}
}

// SetClock replaces the clock (tests).
func (c *Cache[V]) SetClock(now func() time.Time) { c.now = now }

func (c *Cache[V]) gens(k Key) (uint64, uint64) {
	if k.Cross {
		return c.crossGen, c.allGen
	}
	return c.gen[k.Tenant], c.allGen
}

// Get returns the cached value for k, or loads, stores and returns it.
func (c *Cache[V]) Get(k Key, load func() (V, error)) (V, error) {
	if c == nil {
		return load()
	}
	if !k.Cross && k.Tenant == "" {
		return load() // no tenant to key on: never cached
	}
	c.mu.Lock()
	if e, ok := c.entries[k]; ok {
		if c.ttl <= 0 || c.now().Sub(e.at) < c.ttl {
			c.mu.Unlock()
			c.hits.Add(1)
			return c.clone(e.v), nil
		}
		delete(c.entries, k)
		c.expired.Add(1)
	} else {
		c.misses.Add(1)
	}
	g1, g2 := c.gens(k)
	c.mu.Unlock()

	v, err := load()
	if err != nil {
		var zero V
		return zero, err
	}
	c.mu.Lock()
	if n1, n2 := c.gens(k); n1 == g1 && n2 == g2 { // nothing was invalidated while loading
		if len(c.entries) >= c.max {
			c.evictOldest()
		}
		c.seq++
		c.entries[k] = entry[V]{v: c.clone(v), at: c.now(), seq: c.seq}
	}
	c.mu.Unlock()
	return v, nil
}

func (c *Cache[V]) evictOldest() {
	var oldest Key
	var min uint64
	first := true
	for k, e := range c.entries {
		if first || e.seq < min {
			oldest, min, first = k, e.seq, false
		}
	}
	if !first {
		delete(c.entries, oldest)
	}
}

// InvalidateTenant drops the tenant's entries and every cross-tenant entry.
func (c *Cache[V]) InvalidateTenant(tenant string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen[tenant]++
	c.crossGen++
	for k := range c.entries {
		if k.Cross || k.Tenant == tenant {
			delete(c.entries, k)
		}
	}
	c.invalidations.Add(1)
}

// InvalidateAll drops everything (a cross-tenant write: any tenant may have changed).
func (c *Cache[V]) InvalidateAll() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allGen++
	c.crossGen++
	clear(c.entries)
	c.invalidations.Add(1)
}

// Stats is a cache's counters.
type Stats struct {
	Name                                          string
	Hits, Misses, Expired, Invalidations, Entries int64
}

// Stats reports the counters.
func (c *Cache[V]) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	c.mu.Lock()
	n := int64(len(c.entries))
	c.mu.Unlock()
	return Stats{Name: c.name, Hits: c.hits.Load(), Misses: c.misses.Load(), Expired: c.expired.Load(),
		Invalidations: c.invalidations.Load(), Entries: n}
}

// StatsSource is anything with Stats (every Cache).
type StatsSource interface{ Stats() Stats }

// Write renders Prometheus text for the caches. Labels are the cache NAME and
// a closed result enum — never a tenant.
func Write(w io.Writer, caches ...StatsSource) error {
	var all []Stats
	for _, c := range caches {
		if c != nil {
			all = append(all, c.Stats())
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	if _, err := fmt.Fprint(w, "# HELP netops_iris_cache_requests_total Iris per-tenant cache reads by result (N-H4).\n# TYPE netops_iris_cache_requests_total counter\n"); err != nil {
		return err
	}
	for _, s := range all {
		fmt.Fprintf(w, "netops_iris_cache_requests_total{cache=%q,result=\"hit\"} %d\n", s.Name, s.Hits)
		fmt.Fprintf(w, "netops_iris_cache_requests_total{cache=%q,result=\"miss\"} %d\n", s.Name, s.Misses)
		fmt.Fprintf(w, "netops_iris_cache_requests_total{cache=%q,result=\"expired\"} %d\n", s.Name, s.Expired)
	}
	fmt.Fprint(w, "# HELP netops_iris_cache_invalidations_total Invalidations after a write (N-H4).\n# TYPE netops_iris_cache_invalidations_total counter\n")
	for _, s := range all {
		fmt.Fprintf(w, "netops_iris_cache_invalidations_total{cache=%q} %d\n", s.Name, s.Invalidations)
	}
	fmt.Fprint(w, "# HELP netops_iris_cache_entries Entries held now (N-H4).\n# TYPE netops_iris_cache_entries gauge\n")
	for _, s := range all {
		fmt.Fprintf(w, "netops_iris_cache_entries{cache=%q} %d\n", s.Name, s.Entries)
	}
	return nil
}
