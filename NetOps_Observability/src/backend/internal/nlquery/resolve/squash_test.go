// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package resolve

import "testing"

// A name written with other separators is the same name (lex.Squash): edge1,
// EDGE_1 and "edge 1" are the device the caller calls edge-1. Rung 3 still
// decides on its own, as for the exact name.
func TestNameVariantsResolveToTheSameEntity(t *testing.T) {
	rv := resolverFor(tenantA())
	for _, v := range []string{"edge1", "EDGE_1", "edge 1", "Edge.1"} {
		res := mustResolve(t, rv, v, nil)
		if ids(res) != "device:edge-1" || res.Ambiguous || res.Refs[0].NeedsConfirmation || res.Refs[0].Method != MethodInventoryName {
			t.Errorf("%q → %+v", v, res)
		}
	}
	// A tenant alias written another way: "dfwhq" for the name "dfw-hq".
	if res := mustResolve(t, rv, "DFWHQ", nil); ids(res) != "site:dfw-hq" {
		t.Errorf("dfwhq → %+v", res)
	}
	// A different name never matches: edge-11 is not edge-1.
	if res := mustResolve(t, rv, "edge11", []string{"device"}); ids(res) == "device:edge-1" {
		t.Errorf("edge11 must not be edge-1: %+v", res)
	}
}

// Two visible names that differ only in separators are both offered —
// ambiguous, asked, never one picked.
func TestNameVariantCollisionIsAmbiguous(t *testing.T) {
	w := tenantA()
	w.inv = append(w.inv, Named{Type: "device", ID: "device:edge1-lab", Names: []string{"edge_1"}})
	res := mustResolve(t, resolverFor(w), "edge1", nil)
	if !res.Ambiguous || len(res.Refs) != 2 {
		t.Fatalf("collision must be ambiguous: %+v", res)
	}
}

// §3a: the separator-insensitive match reads the caller's inventory only —
// tenant B's gx-edge-9 is never found as "gxedge9".
func TestNameVariantsNeverReachAnotherTenant(t *testing.T) {
	rv := resolverFor(tenantA())
	for _, v := range []string{"gxedge9", "GX_EDGE_9", "gx edge 9"} {
		for _, ref := range mustResolve(t, rv, v, nil).Refs {
			if ref.EntityID == "device:gx-edge-9" {
				t.Fatalf("%q resolved to tenant B's device", v)
			}
		}
	}
}

// Too short to identify anything: a two-character key never matches by
// separators alone.
func TestSquashKeyNeedsALength(t *testing.T) {
	w := tenantA()
	w.inv = append(w.inv, Named{Type: "device", ID: "device:a-1", Names: []string{"a-1"}})
	if res := mustResolve(t, resolverFor(w), "a1", []string{"device"}); ids(res) == "device:a-1" && res.Refs[0].Method == MethodInventoryName {
		t.Fatalf("a two-character key must not match by separators: %+v", res)
	}
}
