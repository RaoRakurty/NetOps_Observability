// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenant

import (
	"path/filepath"
	"testing"
)

type kvRec struct {
	Tenant string `json:"tenant"`
	ID     string `json:"id"`
	Val    string `json:"val"`
}

func newKV(t *testing.T) *Collection[kvRec] {
	t.Helper()
	kv, err := NewCollection[kvRec](filepath.Join(t.TempDir(), "kv.json"), fileKV{},
		func(r kvRec) string { return r.Tenant },
		func(r kvRec) string { return r.ID })
	if err != nil {
		t.Fatal(err)
	}
	return kv
}

// The primitive must isolate by construction: a non-cross caller never sees,
// reads, or deletes another tenant's record — even with an identical id.
func TestTenantKVIsolation(t *testing.T) {
	kv := newKV(t)
	if err := kv.Upsert(kvRec{"acme", "x", "ACME-X"}); err != nil {
		t.Fatal(err)
	}
	if err := kv.Upsert(kvRec{"globex", "x", "GLOBEX-X"}); err != nil { // same id, other tenant
		t.Fatal(err)
	}

	// All: each tenant sees only its own.
	if a := kv.All("acme", false); len(a) != 1 || a[0].Val != "ACME-X" {
		t.Fatalf("acme All = %+v", a)
	}
	if g := kv.All("globex", false); len(g) != 1 || g[0].Val != "GLOBEX-X" {
		t.Fatalf("globex All = %+v", g)
	}
	// Get: scoped to caller's tenant; identical id does not cross.
	if r, ok := kv.Get("acme", false, "x"); !ok || r.Val != "ACME-X" {
		t.Fatalf("acme Get = %+v ok=%v", r, ok)
	}
	if _, ok := kv.Get("acme", false, "nope"); ok {
		t.Fatal("acme Get unknown id returned ok")
	}
	// Delete: deleting acme's record must not touch globex's same-id record.
	if ok := kv.Delete("acme", false, "x"); !ok {
		t.Fatal("acme should delete its own x")
	}
	if _, ok := kv.Get("globex", false, "x"); !ok {
		t.Fatal("globex record wrongly deleted by acme")
	}
	// Cross (platform owner) sees everything and may reach any tenant's id.
	if all := kv.All("", true); len(all) != 1 { // acme's deleted; globex remains
		t.Fatalf("cross All = %+v, want 1", all)
	}
	if _, ok := kv.Get("", true, "x"); !ok {
		t.Fatal("cross Get should find globex's x")
	}
}

func TestTenantKVPersistAndDelete(t *testing.T) {
	kv := newKV(t)
	kv.Upsert(kvRec{"acme", "a", "A"})
	kv.Upsert(kvRec{"acme", "b", "B"})

	// Reload from disk → same rows.
	re, err := NewCollection[kvRec](kv.path, fileKV{},
		func(r kvRec) string { return r.Tenant },
		func(r kvRec) string { return r.ID })
	if err != nil {
		t.Fatal(err)
	}
	if re.Count() != 2 {
		t.Fatalf("reload count = %d, want 2", re.Count())
	}

	if ok := kv.Delete("acme", false, "a"); !ok {
		t.Fatal("delete own record should succeed")
	}
	if ok := kv.Delete("acme", false, "missing"); ok {
		t.Fatal("delete missing id should report false")
	}
	if got := kv.All("acme", false); len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("after delete = %+v", got)
	}
}
