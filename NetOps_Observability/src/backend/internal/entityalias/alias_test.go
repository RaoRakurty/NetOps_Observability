// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package entityalias

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"netops/backend/internal/nlquery/catalog"
)

// memCollection mirrors tenant.Collection's default-closed semantics.
type memCollection struct{ m map[string]Alias }

func newMem() *memCollection { return &memCollection{m: map[string]Alias{}} }
func (c *memCollection) All(t string, cross bool) []Alias {
	var out []Alias
	for _, a := range c.m {
		if cross || a.TenantID == t {
			out = append(out, a)
		}
	}
	return out
}
func (c *memCollection) Get(t string, cross bool, id string) (Alias, bool) {
	a, ok := c.m[t+"\x00"+id]
	return a, ok && (cross || a.TenantID == t)
}
func (c *memCollection) Upsert(a Alias) error { c.m[a.TenantID+"\x00"+a.Key()] = a; return nil }
func (c *memCollection) Delete(t string, cross bool, id string) bool {
	k := t + "\x00" + id
	if _, ok := c.m[k]; !ok {
		return false
	}
	delete(c.m, k)
	return true
}

func store() *Store { return &Store{C: newMem(), Cat: catalog.MustLoad()} }

func TestPutNormalizesAndIsIdempotentByKey(t *testing.T) {
	s := store()
	a, err := s.Put(Alias{TenantID: "t-a", EntityType: "site", EntityID: "site:dfw-hq", Alias: "  DFW  "})
	if err != nil || a.Norm != "dfw" || a.Source != SourceOperator {
		t.Fatalf("put = %+v %v", a, err)
	}
	if _, err := s.Put(Alias{TenantID: "t-a", EntityType: "site", EntityID: "site:dal-2", Alias: "dfw"}); err != nil {
		t.Fatal(err)
	}
	all := s.List("t-a", false)
	if len(all) != 1 || all[0].EntityID != "site:dal-2" {
		t.Fatalf("the same alias text re-points, never duplicates: %+v", all)
	}
}

func TestValidationRejects(t *testing.T) {
	s := store()
	for name, a := range map[string]Alias{
		"no tenant":      {EntityType: "site", EntityID: "site:x", Alias: "X"},
		"empty":          {TenantID: "t", EntityType: "site", EntityID: "site:x", Alias: "  "},
		"too long":       {TenantID: "t", EntityType: "site", EntityID: "site:x", Alias: strings.Repeat("a", MaxAliasLen+1)},
		"control char":   {TenantID: "t", EntityType: "site", EntityID: "site:x", Alias: "a\x00b"},
		"unknown type":   {TenantID: "t", EntityType: "planet", EntityID: "planet:x", Alias: "X"},
		"bad id":         {TenantID: "t", EntityType: "site", EntityID: "device:x", Alias: "X"},
		"punctuation":    {TenantID: "t", EntityType: "site", EntityID: "site:x", Alias: "---"},
		"unknown source": {TenantID: "t", EntityType: "site", EntityID: "site:x", Alias: "X", Source: "model"},
	} {
		if _, err := s.Put(a); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// §3a: own-only list; a foreign alias cannot be deleted and reads as absent.
func TestTenantIsolation(t *testing.T) {
	s := store()
	for _, tn := range []string{"t-a", "t-b"} {
		if _, err := s.Put(Alias{TenantID: tn, EntityType: "site", EntityID: "site:hq", Alias: "HQ"}); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.List("t-a", false); len(got) != 1 || got[0].TenantID != "t-a" {
		t.Fatalf("tenant A list = %+v", got)
	}
	if err := s.Delete("t-a", false, "site", "hq"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("t-a", false, "site", "hq"); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleting again must be not-found")
	}
	if got := s.List("t-b", false); len(got) != 1 {
		t.Fatal("tenant A's delete must not touch tenant B's alias")
	}
	if got := s.List("", true); len(got) != 1 {
		t.Fatalf("cross view = %+v", got)
	}
}

func TestPerTenantCap(t *testing.T) {
	s := store()
	for i := 0; i < MaxPerTenant; i++ {
		if _, err := s.Put(Alias{TenantID: "t-a", EntityType: "device", EntityID: fmt.Sprintf("device:d%d", i), Alias: fmt.Sprintf("dev %d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Put(Alias{TenantID: "t-a", EntityType: "device", EntityID: "device:x", Alias: "one more"}); !errors.Is(err, ErrFull) {
		t.Fatalf("want ErrFull, got %v", err)
	}
	// Re-pointing an existing alias is allowed at the cap.
	if _, err := s.Put(Alias{TenantID: "t-a", EntityType: "device", EntityID: "device:y", Alias: "dev 0"}); err != nil {
		t.Fatalf("re-pointing at the cap: %v", err)
	}
	// Another tenant has its own budget.
	if _, err := s.Put(Alias{TenantID: "t-b", EntityType: "device", EntityID: "device:x", Alias: "one more"}); err != nil {
		t.Fatal(err)
	}
}
