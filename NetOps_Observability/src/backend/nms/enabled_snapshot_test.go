// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

// enabled_snapshot_test.go — the (tenant, integration id) snapshot the backend's
// alert-ownership rule reads (Runtime.IsEnabled). It decides whether a
// connector alert's tenant_id label is believed, so every way it could widen is
// pinned here: an id alone never matches, a disabled row never matches, an
// empty half never matches, and a store failure never adds a pair.

import (
	"context"
	"errors"
	"testing"
)

// failingListStore is a ConfigStore whose ListEnabled can be made to fail.
type failingListStore struct {
	ConfigStore
	fail bool
}

func (f *failingListStore) ListEnabled(ctx context.Context) ([]Integration, error) {
	if f.fail {
		return nil, errors.New("store down")
	}
	return f.ConfigStore.ListEnabled(ctx)
}

func TestIsEnabledIsKeyedByTheTenantIntegrationPair(t *testing.T) {
	ctx := context.Background()
	mem := NewMemStore()
	for _, ic := range []Integration{
		{Tenant: "t_a", ID: "vmanage-1", Vendor: "cisco_sdwan", Enabled: true},
		{Tenant: "t_b", ID: "vmanage-1", Vendor: "cisco_sdwan", Enabled: true}, // same id, other tenant
		{Tenant: "t_b", ID: "off-1", Vendor: "cisco_sdwan", Enabled: false},
	} {
		if err := mem.Upsert(ctx, ic); err != nil {
			t.Fatal(err)
		}
	}
	rt := NewRuntime(mem, Sinks{}, 0)

	if rt.IsEnabled("t_a", "vmanage-1") {
		t.Fatal("before the first refresh the snapshot must be empty (default-closed)")
	}
	ints, err := rt.RefreshEnabled(ctx)
	if err != nil || len(ints) != 2 {
		t.Fatalf("RefreshEnabled = %d, %v; want the 2 enabled rows", len(ints), err)
	}

	cases := []struct {
		tenant, id string
		want       bool
	}{
		{"t_a", "vmanage-1", true},
		{"t_b", "vmanage-1", true},
		{"T_A ", " vmanage-1", true}, // tenant compares case-insensitively, both trimmed
		{"t_a", "VMANAGE-1", false},  // the id is opaque and case-sensitive
		{"t_c", "vmanage-1", false},  // the id alone is not enough
		{"t_b", "off-1", false},      // disabled rows are not in the snapshot
		{"", "vmanage-1", false},
		{"t_a", "", false},
		{"t_a\x00vmanage-1", "", false}, // a NUL cannot forge a key
		{"t_a", "vmanage-1\x00x", false},
	}
	for _, c := range cases {
		if got := rt.IsEnabled(c.tenant, c.id); got != c.want {
			t.Errorf("IsEnabled(%q, %q) = %v, want %v", c.tenant, c.id, got, c.want)
		}
	}
}

func TestRefreshEnabledReplacesTheSnapshotAndKeepsItOnError(t *testing.T) {
	ctx := context.Background()
	mem := NewMemStore()
	if err := mem.Upsert(ctx, Integration{Tenant: "t_a", ID: "i-1", Vendor: "cisco_sdwan", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	st := &failingListStore{ConfigStore: mem}
	rt := NewRuntime(st, Sinks{}, 0)
	if _, err := rt.RefreshEnabled(ctx); err != nil {
		t.Fatal(err)
	}
	if !rt.IsEnabled("t_a", "i-1") {
		t.Fatal("an enabled integration must be in the snapshot")
	}

	// A store failure keeps the last good snapshot and adds nothing.
	if err := mem.Upsert(ctx, Integration{Tenant: "t_b", ID: "i-2", Vendor: "cisco_sdwan", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	st.fail = true
	if _, err := rt.RefreshEnabled(ctx); err == nil {
		t.Fatal("a failing ListEnabled must be reported")
	}
	if !rt.IsEnabled("t_a", "i-1") {
		t.Error("a transient store failure dropped a still-valid pair")
	}
	if rt.IsEnabled("t_b", "i-2") {
		t.Error("a pair entered the snapshot without a successful read")
	}

	// Disabling an integration removes it on the next successful refresh.
	st.fail = false
	if err := mem.Upsert(ctx, Integration{Tenant: "t_a", ID: "i-1", Vendor: "cisco_sdwan", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RefreshEnabled(ctx); err != nil {
		t.Fatal(err)
	}
	if rt.IsEnabled("t_a", "i-1") {
		t.Error("a disabled integration is still in the snapshot after a refresh")
	}
	if !rt.IsEnabled("t_b", "i-2") {
		t.Error("the refresh did not pick up the newly enabled integration")
	}
}
