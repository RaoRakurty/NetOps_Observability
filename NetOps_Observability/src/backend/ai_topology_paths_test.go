// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_topology_paths_test.go — review 3.9-13: the assistant's path list must
// never be cut in silence, and a device's own paths must never be spent by
// another device's definitions.
//
// The path list was bounded twice without a word: once at 200 scanned path
// DEFINITIONS (applied to the tenant-wide list BEFORE this device's own paths
// were selected out of it) and once at MaxTopologyPaths reported. Both stores
// order definitions by path id — MemStore sorts on PathID, PGCHStore issues
// `ORDER BY tenant_id, path_id` — so the truncation was deterministic: the same
// devices lost the same paths on every turn, forever, and the answer said it was
// complete. Its sibling, aiDeviceNeighbors, has said "INCOMPLETE FOR THIS
// DEVICE" since review 3.9-12; this is the same defect one surface over.

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/discovery"
	"netops/backend/models"
	"netops/backend/pathgraph"
)

const pathTestTenant = "acme"

// pathDef builds one valid definition whose PathID is chosen so the store's
// path-id ordering is under the test's control.
func pathDef(t *testing.T, pathID, vantage, src, dst string) pathgraph.PathDefinition {
	t.Helper()
	return pathgraph.PathDefinition{
		PathID:         pathID,
		SrcEndpointRef: vantage,
		DstEndpointRef: dst,
		SrcAddress:     src,
		DstAddress:     dst,
		Direction:      "forward",
		Protocol:       "icmp",
		VantageID:      vantage,
		NetworkContext: "default",
		Provenance: pathgraph.Provenance{
			TenantID: pathTestTenant, DataClass: pathgraph.DataClassLive,
			Environment: "test", ProducerID: "test", ProvenanceID: "prov-" + pathID,
		},
	}
}

// seedPathDefs loads n definitions owned by OTHER devices — their path ids sort
// BEFORE the subject's, exactly as a store's `ORDER BY path_id` would hand them
// over — plus mine definitions for the subject.
func seedPathDefs(t *testing.T, st pathgraph.Store, others, mine int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < others; i++ {
		d := pathDef(t, fmt.Sprintf("pd-aaa-%05d", i), fmt.Sprintf("other-%03d", i), "192.0.2.7", "198.51.100.9")
		if err := st.UpsertPathDefinition(ctx, d); err != nil {
			t.Fatalf("seed other %d: %v", i, err)
		}
	}
	for i := 0; i < mine; i++ {
		d := pathDef(t, fmt.Sprintf("pd-zzz-%05d", i), "core1", "10.0.0.1", fmt.Sprintf("203.0.113.%d", i+1))
		if err := st.UpsertPathDefinition(ctx, d); err != nil {
			t.Fatalf("seed mine %d: %v", i, err)
		}
	}
}

var pathSubject = models.Device{ID: "core1", Name: "core1", Address: "10.0.0.1"}

// TestAIDevicePaths_SubjectPathsSurviveALargeDefinitionList is the defect
// itself: 400 other-device definitions used to consume the 200-definition scan
// bound before this device was ever looked at, so it came back with NO measured
// path and the assistant narrated that as "no measured path is available".
func TestAIDevicePaths_SubjectPathsSurviveALargeDefinitionList(t *testing.T) {
	s := &server{pathGraph: pathgraph.NewMemStore()}
	seedPathDefs(t, s.pathGraph, 400, 3)

	got, capped := s.aiDevicePaths(context.Background(), pathTestTenant, false, pathSubject)
	if capped {
		t.Error("capped = true: this device has three paths, nothing was cut")
	}
	if len(got) != 3 {
		t.Fatalf("got %d paths, want 3 — other devices' definitions spent the bound before this device was looked at", len(got))
	}
	for _, p := range got {
		if !strings.HasPrefix(p.ID, "pd-zzz-") {
			t.Errorf("path %q is not one of the subject's", p.ID)
		}
	}
}

// TestAIDevicePaths_TruncationIsReported: when the SUBJECT genuinely has more
// paths than one answer can carry, the cut is reported and the count is honest.
func TestAIDevicePaths_TruncationIsReported(t *testing.T) {
	s := &server{pathGraph: pathgraph.NewMemStore()}
	seedPathDefs(t, s.pathGraph, 5, ai.MaxTopologyPaths+7)

	got, capped := s.aiDevicePaths(context.Background(), pathTestTenant, false, pathSubject)
	if !capped {
		t.Fatalf("capped = false with %d of this device's paths cut down to %d — a truncated list that does not say so is read as a complete one",
			ai.MaxTopologyPaths+7, len(got))
	}
	if len(got) != ai.MaxTopologyPaths {
		t.Fatalf("got %d paths, want the cap %d", len(got), ai.MaxTopologyPaths)
	}
}

// TestAITopologyContext_SaysThePathListWasTruncated is the caller's half: the
// cap flag has to reach the ANSWER as a note, the way the neighbour cap does.
func TestAITopologyContext_SaysThePathListWasTruncated(t *testing.T) {
	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	if err := d.Upsert(models.Device{ID: "core1", Name: "core1", Address: "10.0.0.1", TenantID: acme.ID}); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	s := &server{discovery: d, tenants: ts, pathGraph: pathgraph.NewMemStore()}

	// The definitions are stamped with the tenant the claims resolve to.
	ctx := context.Background()
	for i := 0; i < ai.MaxTopologyPaths+4; i++ {
		def := pathDef(t, fmt.Sprintf("pd-zzz-%05d", i), "core1", "10.0.0.1", fmt.Sprintf("203.0.113.%d", i+1))
		def.TenantID = acme.ID
		if err := s.pathGraph.UpsertPathDefinition(ctx, def); err != nil {
			t.Fatalf("seed def %d: %v", i, err)
		}
	}

	claims := jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: acme.ID}
	tc, err := s.aiTopologyContext(claims)(ctx, ai.Principal{}, "core1")
	if err != nil {
		t.Fatalf("TopologyContext: %v", err)
	}
	if len(tc.Paths) != ai.MaxTopologyPaths {
		t.Fatalf("got %d paths, want the cap %d", len(tc.Paths), ai.MaxTopologyPaths)
	}
	var said bool
	for _, n := range tc.Notes {
		if n == aiPathCapNote {
			said = true
		}
	}
	if !said {
		t.Fatalf("the answer carries %d of %d paths and says nothing about it. Notes: %v",
			len(tc.Paths), ai.MaxTopologyPaths+4, tc.Notes)
	}
}
