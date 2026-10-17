// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package iriscache

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func cloneSlice(v []string) []string { return append([]string(nil), v...) }

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func counted(n *int, v []string) func() ([]string, error) {
	return func() ([]string, error) { *n++; return cloneSlice(v), nil }
}

func TestHitMissTTL(t *testing.T) {
	ck := &clock{t: time.Unix(0, 0)}
	c := New("aliases", time.Minute, 10, cloneSlice)
	c.SetClock(ck.now)
	k := Key{Tenant: "t-a"}
	loads := 0
	for i := 0; i < 3; i++ {
		if v, _ := c.Get(k, counted(&loads, []string{"dfw"})); v[0] != "dfw" {
			t.Fatal(v)
		}
	}
	if loads != 1 {
		t.Fatalf("%d loads for three reads inside the TTL", loads)
	}
	ck.t = ck.t.Add(61 * time.Second)
	c.Get(k, counted(&loads, []string{"dfw"}))
	if loads != 2 || c.Stats().Expired != 1 {
		t.Fatalf("an expired entry must reload: loads %d, %+v", loads, c.Stats())
	}
}

// §3a at the cache: two tenants with the same scope never share an entry, and
// a cross-tenant view is its own key.
func TestTenantsNeverShareAnEntry(t *testing.T) {
	c := New("aliases", time.Hour, 10, cloneSlice)
	a, _ := c.Get(Key{Tenant: "t-a"}, func() ([]string, error) { return []string{"A's DFW"}, nil })
	b, _ := c.Get(Key{Tenant: "t-b"}, func() ([]string, error) { return []string{"B's DFW"}, nil })
	x, _ := c.Get(Key{Tenant: "global", Cross: true}, func() ([]string, error) { return []string{"A's DFW", "B's DFW"}, nil })
	if a[0] != "A's DFW" || b[0] != "B's DFW" || len(x) != 2 {
		t.Fatalf("a=%v b=%v x=%v", a, b, x)
	}
	// A warm A never answers B.
	b2, _ := c.Get(Key{Tenant: "t-b"}, func() ([]string, error) { t.Fatal("B must be cached as B"); return nil, nil })
	if b2[0] != "B's DFW" {
		t.Fatalf("CROSS-TENANT LEAK: B read %v", b2)
	}
	// A non-cross caller with no tenant is never cached.
	n := 0
	c.Get(Key{}, counted(&n, nil))
	c.Get(Key{}, counted(&n, nil))
	if n != 2 {
		t.Fatal("an empty tenant must never be cached")
	}
}

func TestInvalidateTenantDropsItAndCrossOnly(t *testing.T) {
	c := New("ctx", time.Hour, 10, cloneSlice)
	n := map[string]*int{"a": new(int), "b": new(int), "x": new(int)}
	read := func() {
		c.Get(Key{Tenant: "t-a"}, counted(n["a"], []string{"a"}))
		c.Get(Key{Tenant: "t-b"}, counted(n["b"], []string{"b"}))
		c.Get(Key{Tenant: "global", Cross: true}, counted(n["x"], []string{"a", "b"}))
	}
	read()
	c.InvalidateTenant("t-a")
	read()
	if *n["a"] != 2 || *n["x"] != 2 || *n["b"] != 1 {
		t.Fatalf("after A's write: a=%d x=%d b=%d (B must stay cached)", *n["a"], *n["x"], *n["b"])
	}
	c.InvalidateAll()
	read()
	if *n["b"] != 2 {
		t.Fatal("InvalidateAll must drop every tenant")
	}
}

// A read that began before a write must not store what it read.
func TestInvalidateDuringLoadDoesNotResurrect(t *testing.T) {
	c := New("ctx", time.Hour, 10, cloneSlice)
	k := Key{Tenant: "t-a"}
	c.Get(k, func() ([]string, error) {
		c.InvalidateTenant("t-a") // the write commits while the old value is being read
		return []string{"stale"}, nil
	})
	v, _ := c.Get(k, func() ([]string, error) { return []string{"fresh"}, nil })
	if v[0] != "fresh" {
		t.Fatalf("a load that raced an invalidation was stored: %v", v)
	}
	// The same for a cross entry and a tenant write.
	x := Key{Tenant: "global", Cross: true}
	c.Get(x, func() ([]string, error) { c.InvalidateTenant("t-b"); return []string{"stale"}, nil })
	if v, _ := c.Get(x, func() ([]string, error) { return []string{"fresh"}, nil }); v[0] != "fresh" {
		t.Fatal("a cross load that raced a tenant write was stored")
	}
}

func TestErrorsAreNotCachedAndValuesAreClones(t *testing.T) {
	c := New("aliases", time.Hour, 10, cloneSlice)
	k := Key{Tenant: "t-a"}
	if _, err := c.Get(k, func() ([]string, error) { return nil, errors.New("store down") }); err == nil {
		t.Fatal("error lost")
	}
	v, err := c.Get(k, func() ([]string, error) { return []string{"b", "a"}, nil })
	if err != nil || len(v) != 2 {
		t.Fatalf("an error must not be cached: %v %v", v, err)
	}
	v[0] = "mutated" // a caller sorting or editing its copy
	again, _ := c.Get(k, func() ([]string, error) { t.Fatal("should hit"); return nil, nil })
	if again[0] != "b" {
		t.Fatalf("a caller's edit reached the cache: %v", again)
	}
}

func TestBoundedEvictsOldest(t *testing.T) {
	c := New("aliases", time.Hour, 2, cloneSlice)
	n := 0
	c.Get(Key{Tenant: "t1"}, counted(&n, nil))
	c.Get(Key{Tenant: "t2"}, counted(&n, nil))
	c.Get(Key{Tenant: "t3"}, counted(&n, nil)) // evicts t1
	if c.Stats().Entries != 2 {
		t.Fatalf("entries %d", c.Stats().Entries)
	}
	c.Get(Key{Tenant: "t1"}, counted(&n, nil))
	if n != 4 {
		t.Fatalf("t1 should have been evicted (loads %d)", n)
	}
}

func TestConcurrentReadsAndWrites(t *testing.T) {
	c := New("ctx", time.Hour, 64, cloneSlice)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tenant := []string{"t-a", "t-b"}[i%2]
			for j := 0; j < 200; j++ {
				v, _ := c.Get(Key{Tenant: tenant}, func() ([]string, error) { return []string{tenant}, nil })
				if v[0] != tenant {
					t.Errorf("CROSS-TENANT LEAK under concurrency: %s read %v", tenant, v)
					return
				}
				if j%50 == 0 {
					c.InvalidateTenant(tenant)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestMetricsCarryNoTenant(t *testing.T) {
	c := New("aliases", time.Hour, 10, cloneSlice)
	c.Get(Key{Tenant: "t-secret"}, func() ([]string, error) { return nil, nil })
	c.Get(Key{Tenant: "t-secret"}, func() ([]string, error) { return nil, nil })
	c.InvalidateTenant("t-secret")
	var b bytes.Buffer
	if err := Write(&b, c, New[string]("network_context", time.Minute, 1, nil)); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		`netops_iris_cache_requests_total{cache="aliases",result="hit"} 1`,
		`netops_iris_cache_requests_total{cache="aliases",result="miss"} 1`,
		`netops_iris_cache_invalidations_total{cache="aliases"} 1`,
		`netops_iris_cache_entries{cache="network_context"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(out, "t-secret") {
		t.Fatal("a tenant reached a metric label")
	}
}
