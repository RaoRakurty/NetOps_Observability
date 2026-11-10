// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nms_bridge_isolation_test.go — §3a isolation for the NMS interface bridge and
// the NMS inventory facts (tracker 387 PR 13a; template: org_isolation_test.go).
//
// Neither surface has a read route of its own: what reaches a tenant is the
// device an address resolves to, and the facts stamped on that device's
// records. So the template's three assertions are made in those terms:
//
//   - own-only: a controller's rows and facts land only on devices its
//     integration's owner owns;
//   - cross-tenant: an address one tenant's controller reports never resolves a
//     device of another tenant, and a fact never crosses;
//   - as_tenant: a tenant the payload or a stored row claims is never read;
//     the owner is the integration's, stamped by the runtime.

import (
	"context"
	"testing"
	"time"

	"netops/backend/internal/ifbridge"
	"netops/backend/internal/invfacts"
	"netops/backend/models"
	"netops/backend/nms"
)

const (
	bridgeTenantA = "t_acme"
	bridgeTenantB = "t_globex"
)

// bridgeIsoDevices: the same box name and system-ip in two tenants, plus a
// platform device. Each tenant's controller reports ITS box.
func bridgeIsoDevices() []models.Device {
	return []models.Device{
		{ID: "acme-edge", Name: "edge-1", Address: "10.0.0.1", TenantID: bridgeTenantA, Source: "snmp",
			Labels: map[string]string{"system_ip": "10.255.0.1"}},
		{ID: "globex-edge", Name: "edge-1", Address: "10.0.0.2", TenantID: bridgeTenantB, Source: "snmp",
			Labels: map[string]string{"system_ip": "10.255.0.1"}},
		{ID: "plat-edge", Name: "edge-1", Address: "10.0.0.3", Source: "snmp",
			Labels: map[string]string{"system_ip": "10.255.0.1"}},
	}
}

// vmanagePayload is one device's interface list; its own tenant fields are
// the kind a hostile or a multi-tenant controller sends.
func vmanagePayload(sysIP, host string, addrs ...string) []byte {
	rows := ""
	for i, a := range addrs {
		if i > 0 {
			rows += ","
		}
		rows += `{"vdevice-name":"` + sysIP + `","vdevice-host-name":"` + host + `","ifname":"Gi` + string(rune('1'+i)) +
			`","ifindex":"` + string(rune('1'+i)) + `","ip-address":"` + a + `","vpn-id":"10","tenant":"` + bridgeTenantB +
			`","as_tenant":"` + bridgeTenantB + `","tenant_id":"` + bridgeTenantB + `"}`
	}
	return []byte(`{"tenant":"` + bridgeTenantB + `","data":[` + rows + `]}`)
}

// runControllerPoll is one integration's poll through the production path:
// transform → owner-strict resolution → the server's sink.
func runControllerPoll(t *testing.T, s *server, res *nms.InventoryResolver, integrationOwner, integrationID string, payload []byte) {
	t.Helper()
	b, err := nms.VManageAutoTransformer{}.TransformStream(integrationOwner, integrationID, "interface_realtime", payload)
	if err != nil {
		t.Fatal(err)
	}
	p := nms.NewPipeline(8)
	p.Resolver, p.KeyKind = res, nms.KeySystemIP
	routed := p.Route(b)
	s.ingestNMSInterfaces(integrationOwner, integrationID, "vmanage", routed.Interfaces)
}

func TestNMSBridgeAddressNeverResolvesAnotherTenantsDevice(t *testing.T) {
	devs := bridgeIsoDevices()
	res := &nms.InventoryResolver{}
	res.Store(nms.BuildInventoryIndex(devs, nil, nil))
	s := &server{ifBridge: ifbridge.NewStore(), ifBridgeMetrics: ifbridge.NewMetrics()}

	// Tenant A's controller reports 172.16.0.1 (only A has it) and 172.16.9.9.
	runControllerPoll(t, s, res, bridgeTenantA, "int-a", vmanagePayload("10.255.0.1", "edge-1", "172.16.0.1", "172.16.9.9"))
	// Tenant B's controller reports 172.16.9.9 too: the same address in two tenants.
	runControllerPoll(t, s, res, bridgeTenantB, "int-b", vmanagePayload("10.255.0.1", "edge-1", "172.16.9.9"))

	st, _ := s.ifBridge.Snapshot(inventoryOwners(devs), time.Now())
	merged := ifbridge.Merge(ifbridge.SNMP{}, st, samePort, inventoryOwners(devs))

	// own-only: each controller's rows land on its own owner's device, never
	// on the other tenant's or the platform's same-named box.
	if merged.Addr["acme-edge"]["172.16.0.1"] == "" || merged.Addr["globex-edge"]["172.16.9.9"] == "" {
		t.Fatalf("rows not on their own owner's device: %v", merged.Addr)
	}
	if _, ok := merged.Addr["globex-edge"]["172.16.0.1"]; ok {
		t.Fatal("tenant A's address landed on tenant B's device")
	}
	if _, ok := merged.Addr["plat-edge"]; ok {
		t.Fatalf("a tenant's controller rows landed on the platform device: %v", merged.Addr["plat-edge"])
	}

	// cross-tenant: tenant B's resolver never finds A's address; the
	// tenant-blind receiver index finds A's device for an address only A
	// holds (and must then prove A's credential), and nobody for an address
	// two tenants hold.
	idx := nms.BuildInventoryIndex(devs, nil, merged.Addr)
	bRes := &nms.InventoryResolver{}
	bRes.Store(idx)
	if id, ok := bRes.Peek(bridgeTenantB, nms.KeyIP, "172.16.0.1", ""); ok {
		t.Fatalf("tenant A's address resolved tenant B's device %q", id)
	}
	if id, ok := bRes.Peek(bridgeTenantA, nms.KeyIP, "172.16.0.1", ""); !ok || id != "acme-edge" {
		t.Fatalf("tenant A's own address: %q %v", id, ok)
	}
	if dev, out := idx.DeviceForAddress("172.16.0.1"); dev != "acme-edge" || out != nms.AddressMatched {
		t.Fatalf("A-only address: %q %v", dev, out)
	}
	if dev, out := idx.DeviceForAddress("172.16.9.9"); dev != "" || out != nms.AddressAmbiguous {
		t.Fatalf("an address two tenants hold named %q (%v)", dev, out)
	}
}

// as_tenant: the payload's tenant fields are never read, and a stored row whose
// tenant does not own the device (a forged or stale cache entry) is dropped,
// never relabelled.
func TestNMSBridgeIgnoresAClaimedTenant(t *testing.T) {
	devs := bridgeIsoDevices()
	res := &nms.InventoryResolver{}
	res.Store(nms.BuildInventoryIndex(devs, nil, nil))
	s := &server{ifBridge: ifbridge.NewStore(), ifBridgeMetrics: ifbridge.NewMetrics()}
	runControllerPoll(t, s, res, bridgeTenantA, "int-a", vmanagePayload("10.255.0.1", "edge-1", "172.16.0.1"))
	st, _ := s.ifBridge.Snapshot(inventoryOwners(devs), time.Now())
	if d := st.Devices["acme-edge"]; d == nil || d.Tenant != bridgeTenantA {
		t.Fatalf("rows not under the integration's owner: %+v", st.Devices)
	}
	if _, ok := st.Devices["globex-edge"]; ok {
		t.Fatal("the payload's as_tenant/tenant moved rows to tenant B")
	}

	// A stored row claiming another owner is dropped on load, never relabelled:
	// internal/ifbridge TestWorkerDropsAStoredRowOfAnotherOwner.
}

// Facts: tenant A's controller states a model, site and role for "edge-1" at
// system-ip 10.255.0.1. Tenant B's and the platform's devices of the same name
// and system-ip never receive them.
func TestNMSFactsNeverCopiedAcrossTenants(t *testing.T) {
	devs := bridgeIsoDevices()
	store := &fakeControllerStore{
		ints: []nms.Integration{{Tenant: bridgeTenantA, ID: "int-a", Vendor: "vmanage", Enabled: true}},
		devs: map[string][]nms.ControllerDevice{"int-a": {{
			TenantID: bridgeTenantA, IntegrationID: "int-a", KeyKind: nms.KeySystemIP, Key: "10.255.0.1", Name: "edge-1",
			Model: "ACME-MODEL", SiteID: "7", Role: nms.RoleEdge,
		}, {
			// A row the store would never return for A (RLS); the fake drops it too.
			TenantID: bridgeTenantB, IntegrationID: "int-a", KeyKind: nms.KeySystemIP, Key: "10.255.0.1", Name: "edge-1",
			Model: "LEAKED", SiteID: "666", Role: nms.RoleManager,
		}}},
	}
	f := invfacts.NewStore()
	if err := f.Refresh(context.Background(), store, resolverOver(devs).Peek); err != nil {
		t.Fatal(err)
	}
	rows, _ := buildEnrichmentRowsFacts(devs, nil, f.Current())
	got := rowsByIdentity(rows)
	if r := got["acme-edge"]; r.Model != "ACME-MODEL" || r.Site != "7" || r.Role != "edge" || r.Tenant != bridgeTenantA {
		t.Fatalf("tenant A's own device: %+v", r)
	}
	for _, id := range []string{"globex-edge", "plat-edge"} {
		if r := got[id]; r.Model != "" || r.Site != "" || r.Role != "" {
			t.Errorf("%s received another tenant's facts: %+v", id, r)
		}
	}
	for _, r := range rows {
		if r.Model == "LEAKED" || r.Site == "666" {
			t.Fatalf("a row outside the integration's owner voted: %+v", r)
		}
	}
	// The shared name "edge-1" is claimed by three owners: omitted whole, facts included.
	if _, ok := got["edge-1"]; ok {
		t.Fatal("an identity three owners claim was exported")
	}
}
