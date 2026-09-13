// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"testing"

	"netops/backend/models"
	"netops/backend/wan"
)

// TestWanPolicyGetWithoutAStoreReturnsTheBaseline pins tracker 285. A server
// built without a WAN policy store used to take a nil-pointer panic out of
// wanPolicyStore.Get, which the recover middleware turned into a 500. A missing
// guard is not an error path (§10): the store's own contract is that it never
// fails closed to "no view", so having no store at all must answer the same way
// an unconfigured tenant does.
func TestWanPolicyGetWithoutAStoreReturnsTheBaseline(t *testing.T) {
	var s *wanPolicyStore
	got := s.Get("acme", false)
	want := wan.MeasurementPolicy{TenantID: "acme"}.WithDefaults()
	if got.TenantID != "acme" {
		t.Fatalf("tenant %q, want acme", got.TenantID)
	}
	if got.WanPattern != want.WanPattern {
		t.Fatalf("pattern %q, want the baseline %q", got.WanPattern, want.WanPattern)
	}
	if len(got.Anchors) != len(want.Anchors) {
		t.Fatalf("%d anchors, want the baseline %d", len(got.Anchors), len(want.Anchors))
	}
}

// TestWanPolicyPutWithoutAStoreIsAnError is the write half: it must report that
// there is nowhere to write to, not panic.
func TestWanPolicyPutWithoutAStoreIsAnError(t *testing.T) {
	var s *wanPolicyStore
	if err := s.Put(WanMeasurementPolicy{TenantID: "acme"}); err == nil {
		t.Fatal("Put on a server with no WAN policy store reported success")
	}
}

// TestWanProjectionWithoutAPolicyStoreServesTheSameView walks the path the bug
// was found on: /api/wan/interfaces → wanInterfaceRows → wanProject → Get. With
// the guard in place the projection is the baseline projection, not a 500.
func TestWanProjectionWithoutAPolicyStoreServesTheSameView(t *testing.T) {
	ifaddr := map[string]map[string]string{"wan-a": {"10.0.0.1": "Ethernet1"}}
	s := newWanTestServer(t, ifaddr, nil)
	s.discovery.Upsert(models.Device{ID: "wan-a", Name: "wan-a", Address: "10.0.0.254", TenantID: "acme"})
	ctx := context.Background()
	want, _, _ := s.wanProject(ctx, wanVis(s, "acme"))
	if len(want) == 0 {
		t.Fatal("the harness projects nothing, so the comparison would prove nothing")
	}

	s.wanPolicy = nil
	got, _, _ := s.wanProject(ctx, wanVis(s, "acme"))
	if len(got) != len(want) {
		t.Fatalf("with no policy store the projection has %d endpoints, want the baseline %d", len(got), len(want))
	}
	rows, err := s.wanInterfaceRows(ctx, wanVis(s, "acme"), nil)
	if err != nil {
		t.Fatalf("wanInterfaceRows: %v", err)
	}
	if len(rows) != len(want) {
		t.Fatalf("with no policy store /api/wan/interfaces has %d rows, want %d", len(rows), len(want))
	}
}

// TestDeviceSiteStoreWithoutAStoreAnswersInsteadOfPanicking is tracker 285's
// SIBLING, found the same way: walking /api/wan/interfaces on a partially-built
// server. wanProject asks deviceSites.Get for every in-scope interface one line
// after it asks wanPolicy.Get, and only the policy store had been guarded — so
// the same route still took a nil-pointer panic out of the projection, which the
// recover middleware turned into a 500 the operator cannot act on (§10).
//
// The reads answer the way a deployment that has placed no device answers; the
// write says there is nowhere to write to.
func TestDeviceSiteStoreWithoutAStoreAnswersInsteadOfPanicking(t *testing.T) {
	var s *deviceSiteStore
	if b, ok := s.Get("acme", false, "wan-a"); ok {
		t.Fatalf("Get on a server with no device-site store reported a binding: %+v", b)
	}
	if m := s.Assignments("acme", false); len(m) != 0 {
		t.Fatalf("Assignments returned %d bindings with no store", len(m))
	}
	if s.Delete("acme", false, "wan-a") {
		t.Fatal("Delete reported that it removed a binding that cannot exist")
	}
	if err := s.Set(DeviceSiteBinding{TenantID: "acme", DeviceID: "wan-a", Site: "hq"}); err == nil {
		t.Fatal("Set on a server with no device-site store reported success")
	}
}

// TestWanInterfacesWithoutADeviceSiteStoreServesTheTable walks the route the
// panic came out of. Without the guard this 500s; with it the table is the same
// table, minus the site column nobody configured.
func TestWanInterfacesWithoutADeviceSiteStoreServesTheTable(t *testing.T) {
	ifaddr := map[string]map[string]string{"wan-a": {"10.0.0.1": "Ethernet1"}}
	s := newWanTestServer(t, ifaddr, nil)
	if err := s.discovery.Upsert(models.Device{ID: "wan-a", Name: "wan-a", Address: "10.0.0.254", TenantID: "acme"}); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	ctx := context.Background()
	want, _, _ := s.wanProject(ctx, wanVis(s, "acme"))
	if len(want) == 0 {
		t.Fatal("the harness projects nothing, so the comparison would prove nothing")
	}

	s.deviceSites = nil
	got, _, err := s.wanProject(ctx, wanVis(s, "acme"))
	if err != nil {
		t.Fatalf("wanProject: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("with no device-site store the projection has %d endpoints, want %d", len(got), len(want))
	}
}
