// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// discovered_device_persistence_test.go — tracker 366, the root half: the SNMP
// scan memory survives a restart into the inventory and into the exports the
// correlation engine reads (device_tenant.csv, the persisted topology), and the
// exports hold their previous state while the SNMP inventory is not complete.
// The Postgres half of the restart scenario and the RLS proof live in
// discovered_devices_pg_isolation_test.go.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/discovery"
	"netops/backend/internal/platformdb"
	"netops/backend/models"
	"netops/backend/topology"
)

var scanCreds366 = []discovery.ScanCredential{{ProfileID: "lab-ro", Target: collectors.Target{Community: "lab"}}}

// newScanSource366 is an SNMP source over 10.77.0.0/29 whose answering set is
// switchable.
func newScanSource366(alive *atomic.Pointer[map[string]string], enabled bool) *discovery.SNMPSource {
	src := discovery.NewSNMPSource(func() discovery.ScanSettings {
		return platformScanSettings(enabled, []string{"10.77.0.0/29"}, scanCreds366)
	}, nil)
	src.SetProbeForTest(func(_ context.Context, tg collectors.Target) (string, string, string, bool) {
		m := alive.Load()
		if m == nil {
			return "", "", "", false
		}
		name, ok := (*m)[tg.Address]
		return name, "cisco", "Cisco IOS XE 17.9", ok
	})
	return src
}

// runRestartScenario is the scenario on one backend: life A finds three devices
// and persists them; life B starts on the same store with a network that
// answers nothing, and before any poll its inventory and its enrichment rows
// already carry the same three devices with their platform ("") tenant.
func runRestartScenario(t *testing.T, store discovery.FoundStore) {
	t.Helper()
	ctx := context.Background()
	three := map[string]string{"10.77.0.1": "edge-a", "10.77.0.2": "edge-b", "10.77.0.3": "edge-c"}
	var alive atomic.Pointer[map[string]string]
	alive.Store(&three)

	srcA := newScanSource366(&alive, true)
	if err := srcA.Restore(ctx, store); err != nil {
		t.Fatalf("life A restore: %v", err)
	}
	aggA := discovery.NewDiscoveryAggregator()
	aggA.Register(srcA)
	aggA.PollOnceForTest(ctx, srcA)
	devsA := aggA.Devices()
	if len(devsA) != 3 {
		t.Fatalf("life A found %d devices, want 3", len(devsA))
	}
	idsA := make([]string, 0, 3)
	for _, d := range devsA {
		idsA = append(idsA, d.ID)
	}
	sort.Strings(idsA)

	// Life B: same store, the network is down.
	alive.Store(nil)
	srcB := newScanSource366(&alive, true)
	if err := srcB.Restore(ctx, store); err != nil {
		t.Fatalf("life B restore: %v", err)
	}
	aggB := discovery.NewDiscoveryAggregator()
	aggB.Register(srcB)
	aggB.RestoreForTest() // Start's restore step, no poll
	devsB := aggB.Devices()
	idsB := make([]string, 0, len(devsB))
	for _, d := range devsB {
		idsB = append(idsB, d.ID)
		if d.TenantID != "" {
			t.Fatalf("restored device %s carries tenant %q, want platform ('')", d.ID, d.TenantID)
		}
	}
	sort.Strings(idsB)
	if strings.Join(idsA, ",") != strings.Join(idsB, ",") {
		t.Fatalf("restart changed the inventory: life A %v, life B %v", idsA, idsB)
	}
	rows := buildEnrichmentRows(devsB)
	have := map[string]string{}
	for _, r := range rows {
		have[r.Identity] = r.Tenant
	}
	for addr, name := range three {
		for _, ident := range []string{addr, name} {
			tenant, ok := have[ident]
			if !ok || tenant != "" {
				t.Fatalf("enrichment row for %s missing or mis-tenanted after restart (%q, %v): %+v", ident, tenant, ok, rows)
			}
		}
	}
	// And the export itself is written (the restore made the source ready).
	s := &server{discovery: aggB}
	dir := t.TempDir()
	if !s.writeTenantEnrichmentOnce(dir) {
		t.Fatal("a restored inventory must be exported")
	}
	b, err := os.ReadFile(filepath.Join(dir, enrichmentFileName))
	if err != nil || !strings.Contains(string(b), "edge-b,") {
		t.Fatalf("export lacks the restored devices: %v %s", err, b)
	}
}

func TestDiscoveredDevicesSurviveARestartFileBackend(t *testing.T) {
	store := discovery.NewFileFoundStore(filepath.Join(t.TempDir(), "discovered_devices.json"), platformdb.FileKV{})
	runRestartScenario(t, store)
}

// TestTenantEnrichmentHeldWhileSNMPNotReady: before the scan memory is restored
// or a sweep has finished, the previous device_tenant.csv stands untouched.
func TestTenantEnrichmentHeldWhileSNMPNotReady(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, enrichmentFileName)
	prev := []byte("identity,tenant_id\nedge-down,t_acme\n")
	if err := os.WriteFile(path, prev, 0o644); err != nil {
		t.Fatal(err)
	}
	var alive atomic.Pointer[map[string]string]
	alive.Store(&map[string]string{"10.77.0.4": "edge-up"})
	src := newScanSource366(&alive, true) // no Restore: nothing remembered, nothing polled
	agg := discovery.NewDiscoveryAggregator()
	agg.Register(src)
	s := &server{discovery: agg}
	if s.writeTenantEnrichmentOnce(dir) {
		t.Fatal("the export was written while the SNMP inventory was not complete")
	}
	if b, _ := os.ReadFile(path); string(b) != string(prev) {
		t.Fatalf("the previous file was changed while not ready: %q", b)
	}
	agg.PollOnceForTest(context.Background(), src) // a completed sweep
	if !s.writeTenantEnrichmentOnce(dir) {
		t.Fatal("after a completed sweep the export must be written")
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "edge-up,") {
		t.Fatalf("the export after the sweep lacks the found device: %q", b)
	}
}

// TestReconcilerCarriesNodesForwardWhileSNMPNotReady: a node the registry does
// not list YET is not aged while the SNMP inventory is incomplete; once it is
// complete the node ages normally.
func TestReconcilerCarriesNodesForwardWhileSNMPNotReady(t *testing.T) {
	_, s, _ := newTopoLinkTestServer(t)
	s.topology = newTopologyStore()
	ctx := context.Background()
	s.reconcileTopologyOnce(ctx)
	seeded, err := s.topology.Snapshot(ctx, "", true)
	if err != nil || len(seeded.Nodes) == 0 {
		t.Fatalf("seed: %v %+v", err, seeded)
	}
	old := time.Now().Add(-2 * topologyStaleAfter)
	seeded.Nodes = append(seeded.Nodes, topology.NodeRecord{ID: "edge-down", Label: "edge-down", FirstSeen: old, LastSeen: old})
	if err := s.topology.ReplaceAll(ctx, seeded); err != nil {
		t.Fatal(err)
	}

	var alive atomic.Pointer[map[string]string]
	src := newScanSource366(&alive, false) // registered, never polled: not ready
	s.discovery.Register(src)
	if s.discovery.Ready("snmp") {
		t.Fatal("precondition: the SNMP source must not be ready")
	}
	s.reconcileTopologyOnce(ctx)
	after, err := s.topology.Snapshot(ctx, "", true)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range after.Nodes {
		if n.ID == "edge-down" {
			found = true
			if n.Stale || !n.LastSeen.Equal(old) {
				t.Fatalf("a node was aged while the SNMP inventory was incomplete: %+v", n)
			}
		}
	}
	if !found {
		t.Fatal("a persisted node was dropped while the SNMP inventory was incomplete")
	}

	s.discovery.PollOnceForTest(ctx, src) // disabled poll completes: the inventory is complete (no SNMP devices)
	s.reconcileTopologyOnce(ctx)
	after, err = s.topology.Snapshot(ctx, "", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range after.Nodes {
		if n.ID == "edge-down" && !n.Stale {
			t.Fatal("once the inventory is complete an unobserved node must age as before")
		}
	}
}

// TestDiscoveredDevicesCrossOrgIsolation (§3a, template org_isolation_test.go):
// restored scan memory is served through the same tenant-scoped device API —
// own-only lists, cross-tenant get/delete → 404, ?as_tenant into another org
// ignored, platform rows platform-only, the platform owner sees all.
func TestDiscoveredDevicesCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	type fx struct{ tenantID, token string }
	fix := map[string]*fx{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "scan-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &fx{tenantID: tenantID, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	// A previous life persisted three scanned devices: one platform-scoped,
	// one assigned to each tenant.
	store := discovery.NewFileFoundStore(filepath.Join(t.TempDir(), "discovered_devices.json"), platformdb.FileKV{})
	at := time.Now().UTC().Add(-time.Hour)
	recs := []discovery.FoundRecord{
		{TenantID: "", Source: "snmp", Address: "10.77.0.1", DeviceID: "scan-plat", Name: "scan-plat", FirstFound: at, LastAnswered: at},
		{TenantID: a.tenantID, Source: "snmp", Address: "10.77.0.2", DeviceID: "scan-a", Name: "scan-a", FirstFound: at, LastAnswered: at},
		{TenantID: b.tenantID, Source: "snmp", Address: "10.77.0.3", DeviceID: "scan-b", Name: "scan-b", FirstFound: at, LastAnswered: at},
	}
	if err := store.Apply(context.Background(), recs, nil); err != nil {
		t.Fatal(err)
	}
	var alive atomic.Pointer[map[string]string]
	src := newScanSource366(&alive, true)
	if err := src.Restore(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	s.discovery.Register(src)
	s.discovery.RestoreForTest()

	list := func(token, query string) []string {
		t.Helper()
		st, body := do(t, srv, "GET", "/api/devices"+query, token, nil)
		if st != 200 {
			t.Fatalf("GET /api/devices%s: %d %s", query, st, body)
		}
		var devs []models.Device
		if err := json.Unmarshal(body, &devs); err != nil {
			t.Fatalf("decode devices: %v (%s)", err, body)
		}
		var ids []string
		for _, d := range devs {
			if strings.HasPrefix(d.ID, "scan-") {
				ids = append(ids, d.ID)
			}
		}
		sort.Strings(ids)
		return ids
	}
	if got := list(a.token, ""); strings.Join(got, ",") != "scan-a" {
		t.Fatalf("org A sees %v, want only its own scanned device", got)
	}
	if got := list(b.token, ""); strings.Join(got, ",") != "scan-b" {
		t.Fatalf("org B sees %v, want only its own scanned device", got)
	}
	if got := list(admin, ""); strings.Join(got, ",") != "scan-a,scan-b,scan-plat" {
		t.Fatalf("the platform owner sees %v, want all three", got)
	}
	if st, _ := do(t, srv, "GET", "/api/devices/scan-b", a.token, nil); st != 404 {
		t.Fatalf("org A GET org B's scanned device: %d, want 404", st)
	}
	if st, _ := do(t, srv, "GET", "/api/devices/scan-plat", a.token, nil); st != 404 {
		t.Fatalf("org A GET the platform-scoped scanned device: %d, want 404", st)
	}
	if st, _ := do(t, srv, "DELETE", "/api/devices/scan-b", a.token, nil); st != 404 {
		t.Fatalf("org A DELETE org B's scanned device: %d, want 404", st)
	}
	if got := list(b.token, ""); strings.Join(got, ",") != "scan-b" {
		t.Fatalf("org B's device was affected by A's delete: %v", got)
	}
	// ?as_tenant into another org is ignored (A holds no binding there).
	if got := list(a.token, "?as_tenant="+b.tenantID); strings.Join(got, ",") != "scan-a" {
		t.Fatalf("org A ?as_tenant=%s sees %v, want only its own scanned device", b.tenantID, got)
	}
}
