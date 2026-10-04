// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package resolve

import (
	"context"
	"errors"
	"testing"

	"netops/backend/internal/nlquery/catalog"
)

// fakeLookups is tenant A's world only — tenant B's names are simply absent,
// which is the property the root must guarantee.
type fakeLookups struct{ err error }

func (f fakeLookups) Aliases(context.Context) ([]Alias, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []Alias{
		{EntityType: "site", EntityID: "site:dfw-hq", Alias: "DFW"},
		{EntityType: "site", EntityID: "site:dfw-hq", Alias: "Dallas"},
		{EntityType: "provider", EntityID: "provider:comcast", Alias: "Comcast"},
		{EntityType: "application", EntityID: "app:salesforce", Alias: "SFDC"},
	}, nil
}
func (f fakeLookups) Inventory(_ context.Context, types []string) ([]Named, error) {
	all := []Named{
		{Type: "site", ID: "site:dfw-hq", Names: []string{"Dallas HQ", "dfw-hq"}},
		{Type: "site", ID: "site:aus-br", Names: []string{"Austin Branch", "aus-br"}},
		{Type: "device", ID: "device:edge-1", Names: []string{"edge-1"}},
		{Type: "device", ID: "device:edge-2", Names: []string{"edge-2"}},
		{Type: "application", ID: "app:salesforce", Names: []string{"Salesforce"}},
	}
	var out []Named
	for _, n := range all {
		if contains(types, n.Type) {
			out = append(out, n)
		}
	}
	return out, nil
}
func (f fakeLookups) Visible(_ context.Context, _ string, id string) (bool, error) {
	return id == "site:dfw-hq" || id == "device:edge-1", nil
}

var r = Resolver{Cat: catalog.MustLoad(), L: fakeLookups{}}

func one(t *testing.T, text string, types []string, wantID, wantMethod string) Ref {
	t.Helper()
	res, err := r.Resolve(context.Background(), text, types)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ambiguous || len(res.Refs) != 1 || res.Refs[0].EntityID != wantID || res.Refs[0].Method != wantMethod {
		t.Fatalf("Resolve(%q) = %+v, want %s via %s", text, res, wantID, wantMethod)
	}
	return res.Refs[0]
}

func TestLadder(t *testing.T) {
	one(t, "site:dfw-hq", nil, "site:dfw-hq", MethodCanonicalID)
	one(t, "DFW", nil, "site:dfw-hq", MethodTenantAlias)
	one(t, "dallas", nil, "site:dfw-hq", MethodTenantAlias)
	one(t, "Dallas HQ", nil, "site:dfw-hq", MethodInventoryName)
	one(t, "edge-1", nil, "device:edge-1", MethodInventoryName)
	one(t, "sfdc", nil, "app:salesforce", MethodTenantAlias)
	if ref := one(t, "Austin", nil, "site:aus-br", MethodPartialName); !ref.NeedsConfirmation || ref.Confidence >= 0.97 {
		t.Fatalf("a partial match must need confirmation and rank below exact: %+v", ref)
	}
}

// A canonical id the caller cannot see does not resolve — and then falls
// through as ordinary text, so it cannot be used to probe existence.
func TestInvisibleCanonicalIDDoesNotResolve(t *testing.T) {
	res, err := r.Resolve(context.Background(), "site:tenant-b-hq", nil)
	if err != nil || len(res.Refs) != 0 {
		t.Fatalf("got %+v %v", res, err)
	}
}

func TestAmbiguityIsReportedNotGuessed(t *testing.T) {
	res, err := r.Resolve(context.Background(), "edge", []string{"device"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Ambiguous || len(res.Refs) != 2 {
		t.Fatalf("\"edge\" must be ambiguous between edge-1 and edge-2: %+v", res)
	}
}

func TestTypeRestriction(t *testing.T) {
	res, _ := r.Resolve(context.Background(), "DFW", []string{"device"})
	if len(res.Refs) != 0 {
		t.Fatalf("a site alias must not satisfy a device-only slot: %+v", res)
	}
}

func TestShortTextNeverPartialMatches(t *testing.T) {
	res, _ := r.Resolve(context.Background(), "ed", nil)
	if len(res.Refs) != 0 {
		t.Fatalf("two letters must not partially match: %+v", res)
	}
}

func TestLookupErrorsPropagate(t *testing.T) {
	bad := Resolver{Cat: catalog.MustLoad(), L: fakeLookups{err: errors.New("store down")}}
	if _, err := bad.Resolve(context.Background(), "DFW", nil); err == nil {
		t.Fatal("a failing alias store must surface, not resolve to nothing")
	}
}
