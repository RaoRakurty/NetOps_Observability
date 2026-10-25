// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenant

import (
	"sort"
	"strings"
	"testing"
)

// Tracker 365: the Provider scope ("global", non-cross) owns the platform's
// records in BOTH spellings — device-site bindings are keyed by the device's
// tenant, which is "" for untagged platform devices — while a real tenant id
// never reaches either spelling, and the platform never reaches a tenant.
func TestCollectionPlatformOwnerAliasing(t *testing.T) {
	kv := newKV(t)
	for _, r := range []kvRec{
		{Tenant: "", ID: "blank", Val: "P-BLANK"},
		{Tenant: Global, ID: "glob", Val: "P-GLOBAL"},
		{Tenant: "t_acme", ID: "acme", Val: "ACME"},
		{Tenant: "t_acme", ID: "shared", Val: "ACME-SHARED"},
		{Tenant: "", ID: "shared", Val: "P-SHARED"},
	} {
		if err := kv.Upsert(r); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(rs []kvRec) string {
		out := make([]string, 0, len(rs))
		for _, r := range rs {
			out = append(out, r.Val)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	if got := ids(kv.All(Global, false)); got != "P-BLANK,P-GLOBAL,P-SHARED" {
		t.Fatalf("All(global) = %s, want the platform's rows in both spellings only", got)
	}
	if got := ids(kv.All("", false)); got != "P-BLANK,P-GLOBAL,P-SHARED" {
		t.Fatalf("All(\"\") = %s, want the same owner as global", got)
	}
	if got := ids(kv.All("t_acme", false)); got != "ACME,ACME-SHARED" {
		t.Fatalf("All(t_acme) = %s, want own only", got)
	}
	if r, ok := kv.Get(Global, false, "blank"); !ok || r.Val != "P-BLANK" {
		t.Fatalf("Get(global, blank) = %+v %v, want the '' record", r, ok)
	}
	if r, ok := kv.Get("", false, "glob"); !ok || r.Val != "P-GLOBAL" {
		t.Fatalf("Get('', glob) = %+v %v, want the global record", r, ok)
	}
	if r, ok := kv.Get(Global, false, "shared"); !ok || r.Val != "P-SHARED" {
		t.Fatalf("Get(global, shared) = %+v %v, want the platform's, never t_acme's", r, ok)
	}
	if _, ok := kv.Get(Global, false, "acme"); ok {
		t.Fatal("Get(global, acme) must not reach a tenant's record")
	}
	if _, ok := kv.Get("t_acme", false, "blank"); ok {
		t.Fatal("Get(t_acme, blank) must not reach a platform record")
	}
	if kv.Delete(Global, false, "acme") {
		t.Fatal("Delete(global, acme) must not delete a tenant's record")
	}
	if kv.Delete("t_acme", false, "glob") {
		t.Fatal("Delete(t_acme, glob) must not delete a platform record")
	}
	if !kv.Delete(Global, false, "blank") {
		t.Fatal("Delete(global, blank) must delete the platform's own '' record")
	}
	if _, ok := kv.Get("", true, "blank"); ok {
		t.Fatal("blank record survived its delete")
	}
	if r, ok := kv.Get("t_acme", false, "shared"); !ok || r.Val != "ACME-SHARED" {
		t.Fatalf("t_acme's record with a colliding id was disturbed: %+v %v", r, ok)
	}
}
