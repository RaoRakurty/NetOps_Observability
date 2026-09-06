// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"testing"

	"netops/backend/cloud"
)

// CLAUDE.md §3a: the cloud inventory store enforces tenant isolation — a scoped
// tenant sees only its own resources/mappings; the platform owner (cross) sees all.
func TestCloudStoreIsolation(t *testing.T) {
	ctx := context.Background()
	st := newCloudStore()
	_ = st.ReplaceInventory(ctx, "org-a",
		[]cloud.CloudResource{{ResourceID: "a1", AppID: "billing"}},
		[]cloud.CloudIdentityMapping{{MatchKeyType: cloud.MatchPrivateIP, MatchKey: "10.0.0.1", AppID: "billing"}})
	_ = st.ReplaceInventory(ctx, "org-b",
		[]cloud.CloudResource{{ResourceID: "b1", AppID: "payroll"}}, nil)

	a, _ := st.ListResources(ctx, "org-a", false)
	if len(a) != 1 || a[0].ResourceID != "a1" || a[0].TenantID != "org-a" {
		t.Fatalf("org-a should see only a1 (stamped org-a), got %+v", a)
	}
	b, _ := st.ListResources(ctx, "org-b", false)
	if len(b) != 1 || b[0].ResourceID != "b1" {
		t.Fatalf("org-b leak: %+v", b)
	}
	// platform owner (cross) sees both tenants
	all, _ := st.ListResources(ctx, "", true)
	if len(all) != 2 {
		t.Fatalf("cross should see 2, got %d", len(all))
	}
	// mappings are tenant-scoped too
	ma, _ := st.ListMappings(ctx, "org-a", false)
	mb, _ := st.ListMappings(ctx, "org-b", false)
	if len(ma) != 1 || len(mb) != 0 {
		t.Fatalf("mapping isolation wrong: a=%d b=%d", len(ma), len(mb))
	}

	// ReplaceInventory is a full refresh per tenant
	_ = st.ReplaceInventory(ctx, "org-a", []cloud.CloudResource{{ResourceID: "a2", AppID: "x"}}, nil)
	a, _ = st.ListResources(ctx, "org-a", false)
	if len(a) != 1 || a[0].ResourceID != "a2" {
		t.Fatalf("replace should swap the whole inventory, got %+v", a)
	}
}

// Connector provenance obeys the same isolation contract as the inventory it
// describes: own-only for a scoped tenant, all for cross, full refresh on replace.
func TestCloudStoreConnectorIsolation(t *testing.T) {
	ctx := context.Background()
	st := newCloudStore()
	_ = st.ReplaceConnectors(ctx, "org-a", []cloud.ConnectorInfo{
		{Provider: cloud.AWS, AccountID: "111", Kind: cloud.ConnectorKindLive, ResourceCount: 3}})
	_ = st.ReplaceConnectors(ctx, "org-b", []cloud.ConnectorInfo{
		{Provider: cloud.Azure, AccountID: "222", Kind: cloud.ConnectorKindFixture, ResourceCount: 1}})

	a, _ := st.ListConnectors(ctx, "org-a", false)
	if len(a) != 1 || a[0].AccountID != "111" {
		t.Fatalf("org-a should see only its own connector, got %+v", a)
	}
	b, _ := st.ListConnectors(ctx, "org-b", false)
	if len(b) != 1 || b[0].AccountID != "222" {
		t.Fatalf("org-b leak: %+v", b)
	}
	all, _ := st.ListConnectors(ctx, "", true)
	if len(all) != 2 {
		t.Fatalf("cross should see 2 connectors, got %d", len(all))
	}
	_ = st.ReplaceConnectors(ctx, "org-a", nil)
	a, _ = st.ListConnectors(ctx, "org-a", false)
	if len(a) != 0 {
		t.Fatalf("replace should swap all connectors, got %+v", a)
	}
}
