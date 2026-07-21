package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"netops/backend/pathgraph"
)

// path_graph_retention_test.go — the in-memory path graph store is fed an
// observation per path every 60s, forever, and every read full-scans the slice.
// Unbounded, that is a slow OOM whose read latency degrades in lockstep, so the
// store must evict its oldest rows (and their hops) instead of growing.

func retentionFixtures(tenant string) (pathgraph.PathDefinition, func(id string, at time.Time) (pathgraph.PathObservation, []pathgraph.PathHop)) {
	def := pathgraph.PathDefinition{
		PathID: "pd-retain", SrcAddress: "172.40.40.200", DstAddress: "10.60.10.10",
		Direction: "forward", Protocol: "icmp", VantageID: "lan-vantage-1",
		Provenance: pathgraph.Provenance{TenantID: tenant, DataClass: pathgraph.DataClassLive,
			Environment: "lab", ProvenanceID: "pv-def", ProducerID: "test", RunID: "run-def"},
	}
	mk := func(id string, at time.Time) (pathgraph.PathObservation, []pathgraph.PathHop) {
		o := pathgraph.PathObservation{
			ObservationID: id, PathID: def.PathID, ObservedAt: at, Method: pathgraph.MethodTracerouteICMP,
			VantageID: def.VantageID, Status: pathgraph.StatusComplete, ContractVersion: pathgraph.ContractVersion,
			Provenance: pathgraph.Provenance{TenantID: tenant, DataClass: pathgraph.DataClassLive,
				Environment: "lab", ProvenanceID: "pv-" + id, ProducerID: "test", RunID: "run-" + id},
		}
		hops := []pathgraph.PathHop{{
			ObservationID: id, HopIndex: 1, State: pathgraph.HopResponding, ObservedAddress: "172.40.40.1",
			Transformation: pathgraph.TransformNone, ResolutionMethod: pathgraph.MethodUnresolved,
			Confidence: pathgraph.ConfUnknown, Kind: pathgraph.KindUnknown, EvidenceRef: "pv-" + id,
			ObservedAt: at, TenantID: tenant, DataClass: pathgraph.DataClassLive,
		}}
		return o, hops
	}
	return def, mk
}

func TestMemPathGraphStoreEvictsOldestObservations(t *testing.T) {
	const limit = 10
	ctx := context.Background()
	tenant := "t_retain"
	m := newMemPathGraphStoreWithRetention(limit)
	def, mk := retentionFixtures(tenant)
	if err := m.UpsertPathDefinition(ctx, def); err != nil {
		t.Fatalf("upsert def: %v", err)
	}

	base := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	const total = limit * 5
	for i := 0; i < total; i++ {
		o, hops := mk(fmt.Sprintf("ob-%03d", i), base.Add(time.Duration(i)*time.Minute))
		if err := m.AppendObservation(ctx, def, o, hops); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	m.mu.RLock()
	gotObs := len(m.obs[tenant])
	gotHops := len(m.hops[tenant])
	m.mu.RUnlock()
	if gotObs != limit {
		t.Fatalf("observations retained = %d, want %d (append-only leak)", gotObs, limit)
	}
	// Hops must be evicted WITH their observation or the leak just moves one map down.
	if gotHops != limit {
		t.Fatalf("hop sets retained = %d, want %d (orphaned hops leak)", gotHops, limit)
	}

	f := ObservationFilter{DataClasses: []string{pathgraph.DataClassLive}}
	list, err := m.ListObservations(ctx, tenant, false, f)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != limit {
		t.Fatalf("listed %d, want %d", len(list), limit)
	}
	// The newest survive; the oldest are gone.
	if list[0].ObservationID != fmt.Sprintf("ob-%03d", total-1) {
		t.Fatalf("newest = %q, want ob-%03d", list[0].ObservationID, total-1)
	}
	for _, o := range list {
		if o.ObservationID == "ob-000" {
			t.Fatal("oldest observation was not evicted")
		}
	}
	// The latest observation still resolves with its hops intact.
	latest, hops, _, ok, err := m.LatestObservation(ctx, tenant, false, f)
	if err != nil || !ok {
		t.Fatalf("latest: ok=%v err=%v", ok, err)
	}
	if latest.ObservationID != fmt.Sprintf("ob-%03d", total-1) || len(hops) != 1 {
		t.Fatalf("latest = %q with %d hops", latest.ObservationID, len(hops))
	}
}

// Eviction is per tenant: a chatty tenant must not push another tenant's
// history out of the store.
func TestMemPathGraphStoreEvictionIsPerTenant(t *testing.T) {
	ctx := context.Background()
	m := newMemPathGraphStoreWithRetention(3)
	base := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)

	for _, tenant := range []string{"noisy", "quiet"} {
		def, mk := retentionFixtures(tenant)
		n := 1
		if tenant == "noisy" {
			n = 20
		}
		for i := 0; i < n; i++ {
			o, hops := mk(fmt.Sprintf("%s-%03d", tenant, i), base.Add(time.Duration(i)*time.Minute))
			if err := m.AppendObservation(ctx, def, o, hops); err != nil {
				t.Fatalf("append: %v", err)
			}
		}
	}

	f := ObservationFilter{DataClasses: []string{pathgraph.DataClassLive}}
	noisy, err := m.ListObservations(ctx, "noisy", false, f)
	if err != nil {
		t.Fatal(err)
	}
	quiet, err := m.ListObservations(ctx, "quiet", false, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(noisy) != 3 {
		t.Fatalf("noisy retained %d, want 3", len(noisy))
	}
	if len(quiet) != 1 {
		t.Fatalf("quiet tenant lost history to the noisy one: %d, want 1", len(quiet))
	}
}

// Retention 0 keeps the previous unbounded behaviour available for callers that
// deliberately want it (tests/fixtures) — but it is NOT the default.
func TestMemPathGraphStoreRetentionDisabled(t *testing.T) {
	ctx := context.Background()
	tenant := "t_unbounded"
	m := newMemPathGraphStoreWithRetention(0)
	def, mk := retentionFixtures(tenant)
	base := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 25; i++ {
		o, hops := mk(fmt.Sprintf("ob-%03d", i), base.Add(time.Duration(i)*time.Minute))
		if err := m.AppendObservation(ctx, def, o, hops); err != nil {
			t.Fatal(err)
		}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.obs[tenant]) != 25 {
		t.Fatalf("retained %d, want all 25 when the cap is disabled", len(m.obs[tenant]))
	}
	if got := newMemPathGraphStore().maxObs; got != defaultPathObsRetention {
		t.Fatalf("default store retention = %d, want %d", got, defaultPathObsRetention)
	}
}
