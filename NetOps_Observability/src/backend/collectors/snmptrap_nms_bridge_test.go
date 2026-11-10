// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// snmptrap_nms_bridge_test.go — cEDGE-81 end to end (tracker 387 PR 13a, with
// 13c'): vManage's interface list → owner-strict device resolution → the
// interface bridge → the address index → the trap receiver, with the real
// community proof. Uses the interface list the main session read on 2026-11-10
// (nms/testdata/cedge81_interfaces_2026-11-10.json); no credential is read.
//
// cEDGE-81 answers no SNMP walk, so before 13a no bridge row named
// 192.168.200.33 and 57 % of the lab's traps stayed unattributed.

import (
	"os"
	"testing"
	"time"

	"netops/backend/internal/ifbridge"
	"netops/backend/models"
	"netops/backend/nms"
)

const (
	retailWalmart = "t_c8afbc3445ca56b4fa54887d3e548c27"
	labCommunity  = "labcomm"
)

// labInventory is the lab inventory: the SNMP-scanned cEdges (platform owned),
// cedge-40's own SNMP rows (including the shared internal Loopback65528).
// extra is appended as-is.
func labInventory(cedge81 models.Device, extra ...models.Device) []models.Device {
	return append([]models.Device{
		cedge81,
		{ID: "cedge-40-b99e47eb", Name: "cEDGE-40", Address: "192.168.222.107", Source: "snmp"},
		{ID: "cedge-60-2199eef8", Name: "cEDGE-60", Address: "192.168.222.108", Source: "snmp"},
	}, extra...)
}

var labSNMPAddr = map[string]map[string]string{
	"cedge-40-b99e47eb": {"192.168.222.107": "Loopback200", "192.168.200.25": "GigabitEthernet3", "192.168.1.1": "Loopback65528"},
	"cedge-60-2199eef8": {"192.168.222.108": "Loopback200", "192.168.200.41": "GigabitEthernet3", "192.168.1.1": "Loopback65528"},
}

// bridgeFromVManage runs the controller path: transform, owner-strict
// resolution (integration owned by integrationOwner), store, snapshot, merge.
func bridgeFromVManage(t *testing.T, devs []models.Device, integrationOwner string) (ifbridge.Merged, map[string]int) {
	t.Helper()
	raw, err := os.ReadFile("../nms/testdata/cedge81_interfaces_2026-11-10.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := nms.VManageAutoTransformer{}.TransformStream(integrationOwner, "nmsi-668f5b96d5ce7857", "interface_realtime", raw)
	if err != nil {
		t.Fatal(err)
	}
	res := &nms.InventoryResolver{}
	// The controller-key resolver indexes the SNMP addresses only.
	res.Store(nms.BuildInventoryIndex(devs, nil, labSNMPAddr))
	p := nms.NewPipeline(8)
	p.Resolver, p.KeyKind = res, nms.KeySystemIP
	routed := p.Route(b)

	store := ifbridge.NewStore()
	recs := make([]ifbridge.Record, 0, len(routed.Interfaces))
	for _, c := range routed.Interfaces {
		recs = append(recs, ifbridge.Record{DeviceID: c.DeviceID, Resolve: c.Resolve, At: c.Time,
			Row: ifbridge.Row{IfIndex: c.IfIndex, IfName: c.IfName, VRF: c.VRF, Alias: c.Description, Addrs: c.Addrs}})
	}
	now := time.Now()
	store.Ingest(integrationOwner, "nmsi-668f5b96d5ce7857", "vmanage", recs, now)
	owners := map[string]string{}
	for _, d := range devs {
		owners[d.ID] = d.TenantID
	}
	st, _ := store.Snapshot(owners, now)
	return ifbridge.Merge(ifbridge.SNMP{Addr: labSNMPAddr}, st, nil, owners), store.IngestCounts()
}

// labTrapTargets are the receiver's targets: the SNMP-collected devices, with
// the community Correlix holds for each. A controller-only device is never a
// target (main.go: it is not polled directly).
func labTrapTargets(devs []models.Device) []Target {
	var out []Target
	for _, d := range devs {
		if d.Source == "api" {
			continue
		}
		out = append(out, Target{ID: d.ID, Name: d.Name, Address: d.Address, Community: labCommunity, TenantID: d.TenantID})
	}
	return out
}

func trapFrom(t *testing.T, r *trapReceiver, community, src string) *TrapEvent {
	t.Helper()
	ev, err := r.decodePacket(buildV2cTrap(community), src)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// The acceptance case: the controller and the SNMP twin have ONE owner (the
// twin merged in discovery, so it carries the controller's system_ip). A trap
// from 192.168.200.33 (GigabitEthernet3, VPN 200, unique) names
// cedge-81-11060ae2 by interface address and still has to prove the device's
// community.
func TestCEDGE81TrapAttributesThroughTheNMSBridge(t *testing.T) {
	cedge81 := models.Device{ID: "cedge-81-11060ae2", Name: "cEDGE-81", Address: "192.168.222.106", Source: "snmp",
		Labels: map[string]string{"system_ip": "10.255.255.81", "source_system": "vmanage"}}
	devs := labInventory(cedge81)
	merged, counts := bridgeFromVManage(t, devs, "global")
	if got := merged.Addr["cedge-81-11060ae2"]["192.168.200.33"]; got != "GigabitEthernet3" {
		t.Fatalf("192.168.200.33 not bridged to cedge-81 (got %q); counts %v", got, counts)
	}
	if merged.AddrVRF["cedge-81-11060ae2"]["192.168.200.33"] != "200" {
		t.Fatal("the VPN of 192.168.200.33 was not kept")
	}
	if counts[ifbridge.OutcomeInternalVPN] != 1 {
		t.Fatalf("Loopback65528 not skipped and counted: %v", counts)
	}

	idx := nms.BuildInventoryIndex(devs, nil, merged.Addr)
	r := &trapReceiver{targets: func() []Target { return labTrapTargets(devs) }}
	r.SetAddressResolver(func(ip string) (string, bool) {
		dev, out := idx.DeviceForAddress(ip)
		return dev, out == nms.AddressMatched
	})

	ev := trapFrom(t, r, labCommunity, "192.168.200.33")
	if ev.Device != "cedge-81-11060ae2" || ev.AttributionBasis != AttributionInterfaceIP {
		t.Fatalf("trap from 192.168.200.33: device=%q basis=%q, want cedge-81-11060ae2/interface_ip", ev.Device, ev.AttributionBasis)
	}
	// The community check is not weakened: the right address with the wrong
	// community names nobody.
	if ev := trapFrom(t, r, "not-the-community", "192.168.200.33"); ev.Device != "" || ev.AttributionBasis != AttributionNone {
		t.Fatalf("wrong community attributed: device=%q basis=%q", ev.Device, ev.AttributionBasis)
	}
	// 192.168.1.1 is every cEdge's internal loopback: never resolves.
	if ev := trapFrom(t, r, labCommunity, "192.168.1.1"); ev.Device != "" {
		t.Fatalf("the shared internal loopback named %q", ev.Device)
	}
	// Every other VPN's address names the same device (VPN 0, 100).
	for _, src := range []string{"192.1.6.2", "12.12.12.2", "14.14.14.2", "192.168.100.33"} {
		if ev := trapFrom(t, r, labCommunity, src); ev.Device != "cedge-81-11060ae2" {
			t.Errorf("trap from %s: device=%q", src, ev.Device)
		}
	}
	// The management address keeps its own rung.
	if ev := trapFrom(t, r, labCommunity, "192.168.222.106"); ev.Device != "cedge-81-11060ae2" || ev.AttributionBasis != AttributionMgmtIP {
		t.Fatalf("mgmt: device=%q basis=%q", ev.Device, ev.AttributionBasis)
	}
}

// The lab as it stands on 2026-11-10: the vManage integration belongs to
// RETAIL-WALMART, the SNMP-scanned cEdges to the platform. The controller's key
// resolves only to RETAIL-WALMART's own controller-sourced twin (§3a,
// owner-strict), so the rows bridge under that device, never under the
// platform's cedge-81-11060ae2. That twin is not a trap target (Correlix polls
// nothing on it and holds no community for it), so the trap stays unattributed:
// the community proof cannot be made.
func TestCEDGE81TrapAcrossOwnersStaysUnattributed(t *testing.T) {
	cedge81 := models.Device{ID: "cedge-81-11060ae2", Name: "cEDGE-81", Address: "192.168.222.106", Source: "snmp"}
	ctl := models.Device{ID: nms.ControllerDeviceID(retailWalmart, "vmanage", nms.KeySystemIP, "10.255.255.81"),
		Name: "cEDGE-81", Address: "10.255.255.81", TenantID: retailWalmart, Source: "api",
		Labels: map[string]string{"system_ip": "10.255.255.81"}}
	devs := labInventory(cedge81, ctl)
	merged, _ := bridgeFromVManage(t, devs, retailWalmart)
	if _, ok := merged.Addr["cedge-81-11060ae2"]; ok {
		t.Fatalf("RETAIL-WALMART's controller rows reached the platform's device: %v", merged.Addr["cedge-81-11060ae2"])
	}
	if merged.Addr[ctl.ID]["192.168.200.33"] != "GigabitEthernet3" {
		t.Fatalf("rows not bridged under the integration owner's own device: %v", merged.Addr)
	}
	idx := nms.BuildInventoryIndex(devs, nil, merged.Addr)
	r := &trapReceiver{targets: func() []Target { return labTrapTargets(devs) }}
	r.SetAddressResolver(func(ip string) (string, bool) {
		dev, out := idx.DeviceForAddress(ip)
		return dev, out == nms.AddressMatched
	})
	if ev := trapFrom(t, r, labCommunity, "192.168.200.33"); ev.Device != "" || ev.AttributionBasis != AttributionNone {
		t.Fatalf("a trap was attributed across owners: device=%q basis=%q", ev.Device, ev.AttributionBasis)
	}

	// Without RETAIL-WALMART's twin the key resolves to nothing at all: the
	// platform device is never a candidate, and nothing is bridged.
	merged, counts := bridgeFromVManage(t, labInventory(cedge81), retailWalmart)
	if len(merged.Addr["cedge-81-11060ae2"]) != 0 || counts[ifbridge.OutcomeDeviceUnresolved] != 7 {
		t.Fatalf("cross-owner rows: %v, counts %v", merged.Addr, counts)
	}
}

func TestIfAliasRowsUpdate(t *testing.T) {
	a := ifAliasRows{}
	tgs := []Target{{ID: "d1"}, {ID: "d2"}}
	got := a.update(tgs, []deviceOutcome{
		{id: "d1", ifalias: map[string]string{"1": "WAN"}, ifaliasRead: true},
		{id: "d2", ifalias: map[string]string{"3": "LAN"}, ifaliasRead: true},
	})
	if got["d1"]["1"] != "WAN" || got["d2"]["3"] != "LAN" {
		t.Fatalf("first cycle %v", got)
	}
	// d1 unreachable (no id), d2's walk failed: both keep their aliases.
	got = a.update(tgs, []deviceOutcome{{}, {id: "d2", ifaliasRead: false}})
	if got["d1"]["1"] != "WAN" || got["d2"]["3"] != "LAN" {
		t.Fatalf("an unread walk dropped aliases: %v", got)
	}
	// d2 read fully with no descriptions: gone. d1 left the targets: gone.
	got = a.update([]Target{{ID: "d2"}}, []deviceOutcome{{id: "d2", ifaliasRead: true}})
	if len(got) != 0 {
		t.Fatalf("stale aliases published: %v", got)
	}
}
