// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloudtenant

import (
	"reflect"
	"testing"
)

func TestRowsKeyEachResourceByIdUnderItsOwnTenant(t *testing.T) {
	rows, st := Rows([]Resource{
		{ResourceID: "i-b", TenantID: " T_Beta "},
		{ResourceID: "i-a", TenantID: "t_alpha"},
		{ResourceID: "i-a", TenantID: "t_alpha"}, // the same row twice is one owner
		{ResourceID: "i-p", TenantID: ""},        // platform-owned (single-tenant install)
	})
	want := []Row{
		{Identity: "cloud:i-a", Tenant: "t_alpha"},
		{Identity: "cloud:i-b", Tenant: "t_beta"},
		{Identity: "cloud:i-p", Tenant: ""},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %#v, want %#v", rows, want)
	}
	if st != (Stats{Rows: 3}) {
		t.Fatalf("stats = %#v", st)
	}
}

// A resource id two tenants' inventories both list belongs to neither: the
// readers treat the miss as unattributable, never as either tenant (§3a).
func TestAResourceTwoTenantsListIsOmitted(t *testing.T) {
	rows, st := Rows([]Resource{
		{ResourceID: "arn:shared", TenantID: "t_a"},
		{ResourceID: "arn:shared", TenantID: "t_b"},
		{ResourceID: "arn:mine", TenantID: "t_a"},
	})
	if len(rows) != 1 || rows[0].Identity != "cloud:arn:mine" {
		t.Fatalf("rows = %#v, want only cloud:arn:mine", rows)
	}
	if st.Ambiguous != 1 {
		t.Fatalf("ambiguous = %d, want 1", st.Ambiguous)
	}
}

func TestBlankResourceIdsAreSkippedAndCounted(t *testing.T) {
	rows, st := Rows([]Resource{{ResourceID: "  ", TenantID: "t_a"}, {ResourceID: "", TenantID: "t_b"}})
	if len(rows) != 0 || st.Blank != 2 {
		t.Fatalf("rows=%#v stats=%#v", rows, st)
	}
}

// Azure ids are mixed-case paths: the key is the id exactly as the inventory and
// the poller's `index` both carry it — never case-folded, or two distinct
// resources could merge and a lookup could miss.
func TestIdentityKeepsTheResourceIdExactly(t *testing.T) {
	id := "/subscriptions/S1/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/Web-1"
	if got := Identity(id); got != "cloud:"+id {
		t.Fatalf("Identity = %q", got)
	}
	if Identity("   ") != "" {
		t.Fatal("a blank id must have no key")
	}
}

func TestIsReservedCatchesEverySpellingOfTheNamespace(t *testing.T) {
	for _, s := range []string{"cloud:i-1", "Cloud:i-1", " CLOUD:x", "cloud:"} {
		if !IsReserved(s) {
			t.Errorf("IsReserved(%q) = false", s)
		}
	}
	for _, s := range []string{"web-1", "cloudy-host", "10.0.0.1", "cloud-gw:1"} {
		if IsReserved(s) {
			t.Errorf("IsReserved(%q) = true", s)
		}
	}
}
