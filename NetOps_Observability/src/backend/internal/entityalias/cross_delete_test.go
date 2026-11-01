// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package entityalias_test

import (
	"errors"
	"os"
	"testing"

	"netops/backend/internal/entityalias"
	"netops/backend/internal/tenant"
)

type memKV struct{ m map[string][]byte }

func (k *memKV) Load(key string) ([]byte, error) {
	b, ok := k.m[key]
	if !ok {
		return nil, os.ErrNotExist // the real KVs' "absent store"
	}
	return b, nil
}
func (k *memKV) Save(key string, b []byte) error { k.m[key] = b; return nil }

// The REAL tenant.Collection: its cross fallback is what made a Global-view
// DELETE remove an arbitrary tenant's alias. An alias key is a natural key that
// several tenants may hold, so no caller — cross or not — may delete outside
// its own owner.
func TestAliasDeleteNeverCrossesATenant(t *testing.T) {
	c, err := tenant.NewCollection[entityalias.Alias]("aliases.json", &memKV{m: map[string][]byte{}},
		func(a entityalias.Alias) string { return a.TenantID },
		func(a entityalias.Alias) string { return a.Key() })
	if err != nil {
		t.Fatal(err)
	}
	for _, tn := range []string{"tenant-a", "tenant-b"} {
		a := entityalias.Alias{TenantID: tn, EntityType: "device", EntityID: tn + "-core", Alias: "core", Norm: "core"}
		if err := c.Upsert(a); err != nil {
			t.Fatal(err)
		}
	}
	s := &entityalias.Store{C: c}

	// The Global view (tenant "global", cross) holds no "device|core": 404,
	// and neither tenant's alias is touched.
	if err := s.Delete("global", true, "device", "core"); !errors.Is(err, entityalias.ErrNotFound) {
		t.Fatalf("Global-view delete of an alias it does not hold = %v, want ErrNotFound", err)
	}
	if n := len(s.List("", true)); n != 2 {
		t.Fatalf("a Global-view delete removed a tenant's alias: %d left, want 2", n)
	}
	// A tenant deletes its own and only its own.
	if err := s.Delete("tenant-a", false, "device", "core"); err != nil {
		t.Fatalf("own delete: %v", err)
	}
	left := s.List("", true)
	if len(left) != 1 || left[0].TenantID != "tenant-b" {
		t.Fatalf("tenant-a's delete reached another tenant: %+v", left)
	}
}
