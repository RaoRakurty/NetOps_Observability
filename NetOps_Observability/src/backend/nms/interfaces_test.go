// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"netops/backend/models"
)

// interfaces_test.go — the sixth output class (tracker 387 PR 13a): vManage's
// interface list → ControllerInterface, resolved owner-strictly to inventory.

// cedge81Payload is cEDGE-81's interface list (testdata/cedge81_interfaces_
// 2026-11-10.json: names, VPNs and addresses read live by the main session; no
// ifindex was captured, so none is invented).
func cedge81Payload(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/cedge81_interfaces_2026-11-10.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestInterfaceRealtimeEmitsIdentityRecords(t *testing.T) {
	b, err := vmanageInterfaceRealtimeTransform("t1", "i1", readFixture(t, "interface_realtime_cedge40.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Interfaces) != 10 {
		t.Fatalf("cEdge-40: %d interface records, want all 10 rows (the bridge skips the internal VPN itself)", len(b.Interfaces))
	}
	by := map[string]ControllerInterface{}
	for _, c := range b.Interfaces {
		by[c.IfName] = c
	}
	gi3 := by["GigabitEthernet3"]
	if gi3.IfIndex != "3" || gi3.VRF != "200" || !reflect.DeepEqual(gi3.Addrs, []string{"192.168.172.3"}) ||
		gi3.DeviceKey != "10.255.255.40" || gi3.DeviceName != "cEDGE-40" || gi3.TenantID != "t1" || gi3.SourceSystem != "vmanage" {
		t.Fatalf("Gi3: %+v", gi3)
	}
	if by["Loopback65528"].VRF != "65528" {
		t.Fatal("internal VPN row must reach the bridge to be counted and skipped")
	}
	// Metrics are unchanged: the internal VPN still emits none.
	for _, m := range b.Metrics {
		if m.Tags["ifName"] == "Loopback65528" {
			t.Fatal("internal VPN interface became a metric")
		}
	}

	b, err = vmanageInterfaceRealtimeTransform("t1", "i1", readFixture(t, "interface_realtime_vedge20.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ge00 []ControllerInterface
	for _, c := range b.Interfaces {
		if c.IfName == "ge0/0" {
			ge00 = append(ge00, c)
		}
	}
	// vEdge sends one row per address family; numeric ifindex; "a.b.c.d/len".
	if len(ge00) != 2 || ge00[0].IfIndex != "1" || !reflect.DeepEqual(ge00[0].Addrs, []string{"200.20.2.20/24"}) || len(ge00[1].Addrs) != 0 {
		t.Fatalf("vEdge ge0/0: %+v", ge00)
	}
	for _, c := range b.Interfaces {
		if c.IfName == "eth0" && c.Description != "OOB" {
			t.Fatalf("vEdge desc not read: %+v", c)
		}
	}
}

func TestInterfaceRealtimeIPv6AndOddShapes(t *testing.T) {
	raw := `{"data":[
	 {"vdevice-name":"10.0.0.1","ifname":"Gi1","ifindex":5,"ip-address":"-","ipv6-address":"2001:db8::1/64","vpn-id":10},
	 {"vdevice-name":"10.0.0.1","ifname":"Gi2","ifindex":null,"ip-address":null,"ipv6-addrs":["2001:db8::2",{"ipv6-addr":"2001:db8::3"},7],"vpn-id":null},
	 {"vdevice-name":"10.0.0.1","ifname":"Gi3","ipv6-addrs":{"weird":true}},
	 {"vdevice-name":"not-an-ip","ifname":"Gi9","ip-address":"10.9.9.9"},
	 {"vdevice-name":"10.0.0.1","ifname":"  ","ip-address":"10.9.9.8"}
	]}`
	b, err := vmanageInterfaceRealtimeTransform("t1", "i1", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Interfaces) != 3 {
		t.Fatalf("records %+v", b.Interfaces)
	}
	if c := b.Interfaces[0]; c.IfIndex != "5" || c.VRF != "10" || !reflect.DeepEqual(c.Addrs, []string{"2001:db8::1/64"}) {
		t.Fatalf("Gi1 %+v", c)
	}
	if c := b.Interfaces[1]; c.VRF != "" || !reflect.DeepEqual(c.Addrs, []string{"2001:db8::2", "2001:db8::3"}) {
		t.Fatalf("Gi2 %+v", c)
	}
	if c := b.Interfaces[2]; len(c.Addrs) != 0 {
		t.Fatalf("Gi3 %+v", c)
	}
}

// §3a: the tenant on a record is the integration's, passed by the runtime;
// whatever tenant the controller's payload names (vManage's own "tenant":
// "default", a forged "as_tenant") is never read.
func TestInterfaceRecordsIgnoreAPayloadTenant(t *testing.T) {
	raw := `{"tenant":"t_globex","as_tenant":"t_globex","data":[
	 {"vdevice-name":"10.0.0.1","ifname":"Gi1","ip-address":"10.0.0.5","tenant":"t_globex","as_tenant":"t_globex","tenant_id":"t_globex"}]}`
	b, err := vmanageInterfaceRealtimeTransform("t_acme", "i1", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Interfaces) != 1 || b.Interfaces[0].TenantID != "t_acme" {
		t.Fatalf("records %+v", b.Interfaces)
	}
	var got string
	rt := NewRuntime(NewMemStore(), Sinks{UpsertInterfaces: func(tenant, _, _ string, _ []ControllerInterface) { got = tenant }}, 0)
	rt.sinkRouted(context.Background(), Integration{Tenant: "t_acme", ID: "i1", Vendor: "vmanage"}, NewPipeline(8).Route(b))
	if got != "t_acme" {
		t.Fatalf("sink got tenant %q, want the integration's", got)
	}
}

func bridgeLabIndex() *InventoryIndex {
	return BuildInventoryIndex([]models.Device{
		// cEDGE-81 as discovery holds it once its controller twin merged in:
		// the SNMP id, the controller's system_ip label.
		{ID: "cedge-81-11060ae2", Name: "cEDGE-81", Address: "192.168.222.106", Labels: map[string]string{"system_ip": "10.255.255.81"}},
		{ID: "cedge-40-b99e47eb", Name: "cEDGE-40", Address: "192.168.222.107"},
		{ID: "dup-a", Name: "dup", Address: "10.1.1.1"},
		{ID: "dup-b", Name: "dup", Address: "10.1.1.2"},
		{ID: "acme-edge", Name: "acme-edge", Address: "10.255.255.90", TenantID: "t_acme"},
	}, nil, nil)
}

func TestResolveInterfacesOutcomes(t *testing.T) {
	r := &InventoryResolver{}
	r.Store(bridgeLabIndex())
	in := []ControllerInterface{
		{TenantID: "global", DeviceKey: "10.255.255.81", DeviceName: "cEDGE-81", IfName: "Gi3"},
		{TenantID: "global", DeviceKey: "10.255.255.81", DeviceName: "cEDGE-81", IfName: "Gi1"},
		{TenantID: "global", DeviceKey: "10.255.255.77", IfName: "Gi1"},
		{TenantID: "global", DeviceKey: "10.255.255.78", DeviceName: "dup", IfName: "Gi1"},
		// Owner-strict: the platform integration never matches acme's device.
		{TenantID: "global", DeviceKey: "10.255.255.90", DeviceName: "acme-edge", IfName: "Gi1"},
		{TenantID: "t_acme", DeviceKey: "10.255.255.90", IfName: "Gi1"},
	}
	got := resolveInterfaces(r, KeySystemIP, in)
	want := [][2]string{
		{"cedge-81-11060ae2", "matched"}, {"cedge-81-11060ae2", "matched"},
		{"", "no_match"}, {"", "ambiguous"}, {"", "no_match"}, {"acme-edge", "matched"},
	}
	for i, w := range want {
		if got[i].DeviceID != w[0] || got[i].Resolve != w[1] {
			t.Errorf("record %d: %q/%q, want %q/%q", i, got[i].DeviceID, got[i].Resolve, w[0], w[1])
		}
	}
	// One resolver call per (tenant, key): the memo.
	var b strings.Builder
	r.WriteMetrics(&b)
	if !strings.Contains(b.String(), `netops_nms_device_resolve_total{result="matched"} 2`) {
		t.Fatalf("resolver not memoized per key:\n%s", b.String())
	}
	// No resolver, or an opaque key kind: nothing resolves.
	for _, c := range resolveInterfaces(nil, KeySystemIP, in[:1]) {
		if c.DeviceID != "" || c.Resolve != "no_resolver" {
			t.Fatalf("nil resolver: %+v", c)
		}
	}
	for _, c := range resolveInterfaces(r, KeyNone, in[:1]) {
		if c.DeviceID != "" {
			t.Fatalf("opaque key resolved: %+v", c)
		}
	}
}

// plainResolver is a DeviceResolver without outcomes.
type plainResolver map[string]string

func (p plainResolver) ResolveDevice(_ string, _ KeyKind, key, _ string) (string, bool) {
	id, ok := p[key]
	return id, ok
}

func TestResolveInterfacesPlainResolver(t *testing.T) {
	got := resolveInterfaces(plainResolver{"10.0.0.1": "d1"}, KeySystemIP, []ControllerInterface{
		{DeviceKey: "10.0.0.1", IfName: "Gi1"}, {DeviceKey: "10.0.0.2", IfName: "Gi1"},
	})
	if got[0].DeviceID != "d1" || got[0].Resolve != "matched" || got[1].DeviceID != "" || got[1].Resolve != "no_match" {
		t.Fatalf("%+v", got)
	}
}

func TestResolveInterfacesBounds(t *testing.T) {
	in := make([]ControllerInterface, maxInterfacesPerBatch+5)
	for i := range in {
		in[i] = ControllerInterface{IfName: "x", Addrs: make([]string, maxInterfaceAddrs+3)}
	}
	got := resolveInterfaces(nil, KeySystemIP, in)
	if len(got) != maxInterfacesPerBatch || len(got[0].Addrs) != maxInterfaceAddrs {
		t.Fatalf("not bounded: %d records, %d addrs", len(got), len(got[0].Addrs))
	}
}

// Route carries the resolved records; the run loop and the sink take them.
func TestRouteResolvesCEDGE81Interfaces(t *testing.T) {
	r := &InventoryResolver{}
	r.Store(bridgeLabIndex())
	p := NewPipeline(8)
	p.Resolver, p.KeyKind = r, KeySystemIP
	b, err := VManageAutoTransformer{}.TransformStream("global", "nmsi-1", "interface_realtime", cedge81Payload(t))
	if err != nil {
		t.Fatal(err)
	}
	out := p.Route(b)
	if len(out.Interfaces) != 8 {
		t.Fatalf("routed %d records", len(out.Interfaces))
	}
	for _, c := range out.Interfaces {
		if c.DeviceID != "cedge-81-11060ae2" || c.Resolve != "matched" {
			t.Fatalf("record not resolved to the inventory device: %+v", c)
		}
	}
}

func TestInventoryResolverPeekDoesNotCount(t *testing.T) {
	r := &InventoryResolver{}
	if _, ok := r.Peek("global", KeySystemIP, "10.255.255.81", ""); ok {
		t.Fatal("Peek resolved with no index")
	}
	r.Store(bridgeLabIndex())
	id, ok := r.Peek("global", KeySystemIP, "10.255.255.81", "")
	if !ok || id != "cedge-81-11060ae2" {
		t.Fatalf("Peek %q %v", id, ok)
	}
	if _, ok := r.Peek("t_globex", KeySystemIP, "10.255.255.81", ""); ok {
		t.Fatal("Peek crossed an owner")
	}
	var b strings.Builder
	r.WriteMetrics(&b)
	if strings.Contains(b.String(), `} 1`) {
		t.Fatalf("Peek counted:\n%s", b.String())
	}
	if id, o := r.ResolveDeviceOutcome("global", KeySystemIP, "10.255.255.81", ""); id == "" || o != "matched" {
		t.Fatalf("outcome %q %q", id, o)
	}
	if _, o := (&InventoryResolver{}).ResolveDeviceOutcome("global", KeySystemIP, "10.255.255.81", ""); o != "no_index" {
		t.Fatalf("no index: %q", o)
	}
}

func TestVManageFactsMapper(t *testing.T) {
	var m DeviceFactsMapper = VManageFacts{}
	for typ, role := range map[string]string{
		"vedge": RoleEdge, "VEDGE": RoleEdge, "vsmart": RoleController, "vbond": RoleOrchestrator,
		"vmanage": RoleManager, "": "", "vcontainer": "",
	} {
		if got := m.MapFacts(NativeDeviceFacts{DeviceType: typ}).Role; got != role {
			t.Errorf("device-type %q → %q, want %q", typ, got, role)
		}
	}
	f := m.MapFacts(NativeDeviceFacts{Model: " vedge-CSR-1000v\n", SiteID: "81", DeviceType: "vedge"})
	if f != (InventoryFacts{Model: "vedge-CSR-1000v", Site: "81", Role: RoleEdge}) {
		t.Fatalf("facts %+v", f)
	}
	if long := m.MapFacts(NativeDeviceFacts{Model: strings.Repeat("m", 500)}); len(long.Model) != maxDeviceFieldLen {
		t.Fatal("model not bounded")
	}
}

func TestNormalizeRoleIsAClosedSet(t *testing.T) {
	for in, want := range map[string]string{
		"Edge": "edge", " manager ": "manager", "orchestrator": "orchestrator", "switch": "switch",
		"core-router-of-doom": "", "<script>": "", "": "",
	} {
		if got := NormalizeRole(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
	if f := FactsOf(ControllerDevice{Model: "m", SiteID: "40", Role: "weird"}); f.Role != "" || f.Model != "m" || f.Site != "40" {
		t.Fatalf("FactsOf %+v", f)
	}
}

func TestInventoryTransformRolesFromTheMapper(t *testing.T) {
	raw := `{"data":[
	 {"system-ip":"10.255.255.1","host-name":"vManage","device-type":"vmanage","device-model":"vmanage","site-id":250},
	 {"system-ip":"10.255.255.2","host-name":"vSmart","device-type":"vsmart","device-model":"vsmart","site-id":250},
	 {"system-ip":"10.255.255.3","host-name":"vBond","device-type":"vbond","device-model":"vedge-cloud","site-id":250},
	 {"system-ip":"10.255.255.81","host-name":"cEDGE-81","device-type":"vedge","device-model":"vedge-CSR-1000v","site-id":"81"}]}`
	b, err := vmanageInventoryTransform("t1", "i1", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][3]string{
		"10.255.255.1":  {RoleManager, "vmanage", "250"},
		"10.255.255.2":  {RoleController, "vsmart", "250"},
		"10.255.255.3":  {RoleOrchestrator, "vedge-cloud", "250"},
		"10.255.255.81": {RoleEdge, "vedge-CSR-1000v", "81"},
	}
	for _, d := range b.Devices {
		w := want[d.Key]
		if d.Role != w[0] || d.Model != w[1] || d.SiteID != w[2] || d.Managed != (w[0] == RoleEdge) {
			t.Errorf("%s: role=%q model=%q site=%q managed=%v", d.Key, d.Role, d.Model, d.SiteID, d.Managed)
		}
	}
}
