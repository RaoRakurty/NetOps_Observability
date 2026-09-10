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
	want, _ := s.wanProject(ctx, "acme", false)
	if len(want) == 0 {
		t.Fatal("the harness projects nothing, so the comparison would prove nothing")
	}

	s.wanPolicy = nil
	got, _ := s.wanProject(ctx, "acme", false)
	if len(got) != len(want) {
		t.Fatalf("with no policy store the projection has %d endpoints, want the baseline %d", len(got), len(want))
	}
	if rows := s.wanInterfaceRows(ctx, "acme", false, nil); len(rows) != len(want) {
		t.Fatalf("with no policy store /api/wan/interfaces has %d rows, want %d", len(rows), len(want))
	}
}
