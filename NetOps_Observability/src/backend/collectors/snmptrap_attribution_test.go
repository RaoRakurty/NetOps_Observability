// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// Trap source attribution by interface address (tracker 387 PR 13c', §8, §3a).
// The lab's shape: cedge-81's management address is 192.168.222.106, but its
// BGP traps leave from its Gi3 address 192.168.200.33, and 192.168.1.1 is the
// internal Loopback65528 of three cEdges. These tests use a resolver with the
// same contract as nms.InventoryIndex.DeviceForAddress (unique only), and the
// nms package tests that index itself.

import (
	"encoding/json"
	"strings"
	"testing"
)

// uniqueAddrResolver mimics DeviceForAddress: an address held by exactly one
// device names it; an address held by two names nobody.
func uniqueAddrResolver(holders map[string][]string) TrapAddressResolver {
	return func(ip string) (string, bool) {
		devs := holders[ip]
		if len(devs) != 1 {
			return "", false
		}
		return devs[0], true
	}
}

func labTargets() []Target {
	return []Target{
		{ID: "cedge-81-11060ae2", Name: "cEDGE-81", Address: "192.168.222.106", Community: "labcomm"},
		{ID: "cedge-40-aa", Name: "cEDGE-40", Address: "192.168.222.107", Community: "labcomm"},
		{ID: "acme-edge", Name: "acme-edge", Address: "10.1.0.1", Community: "acmecomm", TenantID: "acme"},
	}
}

func labReceiver(holders map[string][]string) *trapReceiver {
	ts := labTargets()
	r := &trapReceiver{targets: func() []Target { return ts }}
	r.SetAddressResolver(uniqueAddrResolver(holders))
	return r
}

// An address one device holds names that device (basis interface_ip); the same
// address on two devices names nobody (basis none).
func TestTrapInterfaceAddrResolvesUniqueOnly(t *testing.T) {
	r := labReceiver(map[string][]string{
		"192.168.200.33": {"cedge-81-11060ae2"},
		"192.168.1.1":    {"cedge-81-11060ae2", "cedge-40-aa"},
	})
	ev, err := r.decodePacket(buildV2cTrap("labcomm"), "192.168.200.33")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "cedge-81-11060ae2" || ev.AttributionBasis != AttributionInterfaceIP || ev.EnrichmentStatus != "inventory_matched" {
		t.Fatalf("unique interface address: device=%q basis=%q status=%q", ev.Device, ev.AttributionBasis, ev.EnrichmentStatus)
	}
	if ev.Host != "192.168.200.33" {
		t.Errorf("host must stay the observed sender, got %q", ev.Host)
	}
	ev, err = r.decodePacket(buildV2cTrap("labcomm"), "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "" || ev.AttributionBasis != AttributionNone {
		t.Fatalf("shared address attributed: device=%q basis=%q", ev.Device, ev.AttributionBasis)
	}
}

// The right address with the wrong community proves nothing: no device.
func TestTrapInterfaceAddrStillRequiresCommunity(t *testing.T) {
	r := labReceiver(map[string][]string{"192.168.200.33": {"cedge-81-11060ae2"}})
	for _, comm := range []string{"wrong", ""} {
		ev, err := r.decodePacket(buildV2cTrap(comm), "192.168.200.33")
		if err != nil {
			t.Fatal(err)
		}
		if ev.Device != "" || ev.AttributionBasis != AttributionNone {
			t.Errorf("community %q: device=%q basis=%q, want none", comm, ev.Device, ev.AttributionBasis)
		}
	}
	// Another device's valid community does not prove THIS device either.
	ev, err := r.decodePacket(buildV2cTrap("acmecomm"), "192.168.200.33")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "" {
		t.Errorf("acme's community claimed cedge-81: device=%q", ev.Device)
	}
}

// The address yields a device ID and nothing else: the event carries no tenant
// and no address-derived identity, so the aggregator's registry lookup is on
// the device id and the tenant is that device's own row.
func TestTrapInterfaceAddrTenantFromDevice(t *testing.T) {
	r := labReceiver(map[string][]string{"172.31.9.9": {"acme-edge"}})
	ev, err := r.decodePacket(buildV2cTrap("acmecomm"), "172.31.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "acme-edge" || ev.AttributionBasis != AttributionInterfaceIP {
		t.Fatalf("device=%q basis=%q, want acme-edge/interface_ip", ev.Device, ev.AttributionBasis)
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"tenant_id", "tenant", "tenant_seg"} {
		if _, ok := doc[k]; ok {
			t.Errorf("the receiver stamped %q: the tenant must come from the device's registry row", k)
		}
	}
	if doc["device"] != "acme-edge" || doc["attribution_basis"] != "interface_ip" {
		t.Errorf("published device/basis = %v/%v", doc["device"], doc["attribution_basis"])
	}
	// A resolver answer naming a device inventory does not know is no answer.
	r2 := labReceiver(map[string][]string{"172.31.9.9": {"ghost"}})
	ev, err = r2.decodePacket(buildV2cTrap("acmecomm"), "172.31.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "" {
		t.Errorf("a device absent from inventory was attributed: %q", ev.Device)
	}
}

// Each rung reports itself, and the set is closed.
func TestTrapAttributionBasisLabelClosedSet(t *testing.T) {
	closed := map[string]bool{
		AttributionMgmtIP: true, AttributionInterfaceIP: true, AttributionSysName: true,
		AttributionAgentAddr: true, AttributionNone: true,
	}
	r := labReceiver(map[string][]string{"192.168.200.33": {"cedge-81-11060ae2"}})
	cases := []struct {
		name, src string
		pkt       []byte
		want      string
	}{
		{"management address", "192.168.222.106", buildV2cTrap("labcomm"), AttributionMgmtIP},
		{"interface address", "192.168.200.33", buildV2cTrap("labcomm"), AttributionInterfaceIP},
		{"sysName", "203.0.113.5", buildV2cSysNameTrap("labcomm", "cEDGE-81"), AttributionSysName},
		{"v1 agent-addr", "203.0.113.5", buildV1Trap("labcomm"), AttributionNone}, // agent-addr 10.0.0.x is no device here
		{"nothing", "203.0.113.5", buildV2cTrap("labcomm"), AttributionNone},
	}
	for _, c := range cases {
		ev, err := r.decodePacket(c.pkt, c.src)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if ev.AttributionBasis != c.want || !closed[ev.AttributionBasis] {
			t.Errorf("%s: basis %q, want %q", c.name, ev.AttributionBasis, c.want)
		}
	}
	// agent_addr: the v1 PDU's own address resolves by management address.
	ts := []Target{{ID: "v1dev", Address: "10.0.0.9", Community: "labcomm"}}
	rv := &trapReceiver{targets: func() []Target { return ts }}
	ev := &TrapEvent{Version: "v1", community: "labcomm", agentAddr: "10.0.0.9"}
	rv.attributeDevice(ev, "172.16.0.1")
	if ev.AttributionBasis != AttributionAgentAddr || ev.Device != "v1dev" {
		t.Errorf("agent_addr rung: device=%q basis=%q", ev.Device, ev.AttributionBasis)
	}
}

// Without the injected index, nothing attributes by interface address: the
// receiver behaves exactly as before 13c'.
func TestTrapInterfaceAddrNoResolverIsTheOldBehaviour(t *testing.T) {
	ts := labTargets()
	r := &trapReceiver{targets: func() []Target { return ts }}
	ev, err := r.decodePacket(buildV2cTrap("labcomm"), "192.168.200.33")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "" || ev.AttributionBasis != AttributionNone {
		t.Fatalf("device=%q basis=%q", ev.Device, ev.AttributionBasis)
	}
	r.SetAddressResolver(nil)
	if _, ok := r.resolveByInterface("192.168.200.33"); ok {
		t.Fatal("a cleared resolver still resolves")
	}
}

// A v3 trap from an interface address is verified with that device's keys,
// and attributed only because the HMAC verified.
func TestTrapInterfaceAddrV3UsesTheDevicesKeys(t *testing.T) {
	creds := snmpCreds{Version: 3, User: "trapuser", Level: "authNoPriv", AuthProto: "SHA", AuthKey: "authpassword123"}
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x01, 0xde, 0xad, 0xbe, 0xef}
	newHash, _ := authHash(creds.AuthProto)
	sess := &v3Session{creds: creds, engineID: engineID, boots: 1, etime: 1}
	sess.authKeyL = localizeKey(newHash, creds.AuthKey, engineID)
	snmpTrapOID := []int{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
	coldStart := []int{1, 3, 6, 1, 6, 3, 1, 1, 5, 1}
	vb := func(oid []int, val []byte) []byte { return berTLV(0x30, append(berOID(oid), val...)) }
	scoped := buildScopedPDU(engineID, "", buildPDU(0xA7, 1, berTLV(0x30, vb(snmpTrapOID, berOID(coldStart)))))
	pkt := buildV3Message(7, creds, sess, scoped, nil)

	ts := []Target{{ID: "v3-edge", Address: "10.5.0.1", SNMPVersion: 3, V3User: creds.User, V3Level: creds.Level,
		V3AuthProto: creds.AuthProto, V3AuthKey: creds.AuthKey}}
	r := &trapReceiver{targets: func() []Target { return ts }}
	r.SetAddressResolver(uniqueAddrResolver(map[string][]string{"10.5.9.9": {"v3-edge"}}))
	ev, err := r.decodePacket(pkt, "10.5.9.9")
	if err != nil {
		t.Fatalf("v3 from an interface address: %v", err)
	}
	if !ev.Authenticated || ev.Device != "v3-edge" || ev.AttributionBasis != AttributionInterfaceIP {
		t.Fatalf("authenticated=%v device=%q basis=%q", ev.Authenticated, ev.Device, ev.AttributionBasis)
	}
	bad := append([]byte(nil), pkt...)
	bad[len(bad)-1] ^= 0xff
	if _, err := r.decodePacket(bad, "10.5.9.9"); err == nil || !strings.Contains(err.Error(), "auth") {
		t.Fatalf("a tampered v3 trap from an interface address must fail auth, got %v", err)
	}
}
