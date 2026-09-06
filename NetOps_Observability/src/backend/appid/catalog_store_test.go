// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

import (
	"context"
	"net/netip"
	"testing"
)

func TestValidateAppCatalogInput(t *testing.T) {
	cases := []struct {
		kind, val, app string
		ok             bool
	}{
		{"prefix", "10.0.0.0/8", "Billing", true},
		{"prefix", "10.0.0.5", "Billing", true},
		{"prefix", "not-a-cidr", "Billing", false},
		{"port", "8443", "Internal", true},
		{"port", "99999", "Internal", false},
		{"domain", "intra.corp", "Wiki", true},
		{"bogus", "x", "y", false},
		{"prefix", "10.0.0.0/8", "", false}, // empty app
	}
	for _, c := range cases {
		err := ValidateCatalogInput(c.kind, c.val, c.app)
		if (err == nil) != c.ok {
			t.Fatalf("validate(%q,%q,%q): ok=%v err=%v", c.kind, c.val, c.app, c.ok, err)
		}
	}
}

func TestAppCatalogStoreIsolation(t *testing.T) {
	ctx := context.Background()
	st := &memCatalogStore{by: map[string]AppCatalogEntry{}}
	a, _ := st.Create(ctx, "org-a", false, AppCatalogEntry{TenantID: "org-a", MatchKind: "prefix", MatchValue: "10.1.0.0/16", AppLabel: "A-App"})
	b, _ := st.Create(ctx, "org-b", false, AppCatalogEntry{TenantID: "org-b", MatchKind: "prefix", MatchValue: "10.2.0.0/16", AppLabel: "B-App"})
	g, _ := st.Create(ctx, "", true, AppCatalogEntry{TenantID: "", MatchKind: "prefix", MatchValue: "10.9.0.0/16", AppLabel: "Shared"})

	// org-a sees its own + the shared global, never org-b's
	la, _ := st.List(ctx, "org-a", false)
	seen := map[string]bool{}
	for _, e := range la {
		seen[e.AppLabel] = true
	}
	if !seen["A-App"] || !seen["Shared"] || seen["B-App"] {
		t.Fatalf("org-a visibility wrong: %+v", la)
	}

	// org-b cannot delete org-a's row, nor the shared global row
	if ok, _ := st.Delete(ctx, "org-b", false, a.CatalogID); ok {
		t.Fatal("org-b deleted org-a's override — cross-tenant leak")
	}
	if ok, _ := st.Delete(ctx, "org-b", false, g.CatalogID); ok {
		t.Fatal("a scoped tenant must not delete the shared global override")
	}
	// org-a can delete its own
	if ok, _ := st.Delete(ctx, "org-a", false, a.CatalogID); !ok {
		t.Fatal("org-a could not delete its own override")
	}
	_ = b
}

func TestBuildOverrideCatalogAuthoritative(t *testing.T) {
	// an operator override resolves as SrcOperator → confirmed, even for an internal
	// RFC1918 IP that no vendor catalog knows.
	entries := []AppCatalogEntry{
		{MatchKind: "prefix", MatchValue: "10.5.0.0/16", AppLabel: "Payroll"},
		{MatchKind: "domain", MatchValue: "wiki.corp", AppLabel: "Wiki"}, // non-prefix: skipped in P1c
	}
	ov := BuildOverrides(entries)
	if ov.Prefixes.Size() != 1 {
		t.Fatalf("only the prefix entry should index as a prefix, size=%d", ov.Prefixes.Size())
	}
	if ov.Domains.Size() != 1 {
		t.Fatalf("the domain entry should index in the domain matcher, size=%d", ov.Domains.Size())
	}
	sigs := ov.Prefixes.SignalsFor(netip.MustParseAddr("10.5.1.2"))
	if len(sigs) != 1 || sigs[0].Source != SrcOperator || sigs[0].App != "Payroll" {
		t.Fatalf("expected an authoritative Payroll signal, got %+v", sigs)
	}
	// fused over an empty global catalog → confirmed
	v := NewCatalog(nil).Resolve(netip.MustParseAddr("10.5.1.2"), sigs...)
	if v.App != "Payroll" || v.Tier != Confirmed {
		t.Fatalf("operator override should confirm Payroll, got %+v", v)
	}
}
