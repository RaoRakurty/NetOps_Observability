// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// Tracker 371 R2: credential-proven traps for CONTROLLER-ONLY devices. A device
// an integration reports and no collector of ours polls has no bound profile;
// the receiver now holds RECEIVE-ONLY identity targets carrying the owner's own
// profiles, consulted only after every direct rung, proving strictly.

import (
	"strings"
	"testing"
)

// roReceiver: the lab's direct targets plus receive-only identity targets.
func roReceiver(recv []Target, holders map[string][]string) *trapReceiver {
	r := labReceiver(holders)
	r.SetReceiveOnlyTargets(func() []Target { return recv })
	return r
}

// buildV3TrapForTest is a coldStart SNMPv3 trap signed (when the level asks for
// it) with creds — the same construction the 13c' v3 test uses.
func buildV3TrapForTest(t *testing.T, creds snmpCreds) []byte {
	t.Helper()
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x01, 0xca, 0xfe, 0xba, 0xbe}
	sess := &v3Session{creds: creds, engineID: engineID, boots: 1, etime: 1}
	if creds.wantsAuth() {
		newHash, _ := authHash(creds.AuthProto)
		sess.authKeyL = localizeKey(newHash, creds.AuthKey, engineID)
	}
	snmpTrapOID := []int{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
	coldStart := []int{1, 3, 6, 1, 6, 3, 1, 1, 5, 1}
	vb := func(oid []int, val []byte) []byte { return berTLV(0x30, append(berOID(oid), val...)) }
	scoped := buildScopedPDU(engineID, "", buildPDU(0xA7, 1, berTLV(0x30, vb(snmpTrapOID, berOID(coldStart)))))
	return buildV3Message(9, creds, sess, scoped, nil)
}

func acmeCtl(addr string, community string) Target {
	return Target{ID: "ctl-vmanage-acme1", Name: "acme-branch-9", Address: addr, TenantID: "acme",
		Community: community, ReceiveOnly: true}
}

func TestReceiveOnlyTenantCommunityProvesTheDevice(t *testing.T) {
	r := roReceiver([]Target{acmeCtl("10.200.0.1", "acmecomm")},
		map[string][]string{"192.0.2.50": {"ctl-vmanage-acme1"}})
	ev, err := r.decodePacket(buildV2cTrap("acmecomm"), "10.200.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "ctl-vmanage-acme1" || ev.AttributionBasis != AttributionMgmtIP || ev.DeviceName != "acme-branch-9" {
		t.Fatalf("management address + owner's community: device=%q basis=%q name=%q", ev.Device, ev.AttributionBasis, ev.DeviceName)
	}
	ev, err = r.decodePacket(buildV2cTrap("acmecomm"), "192.0.2.50")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "ctl-vmanage-acme1" || ev.AttributionBasis != AttributionInterfaceIP {
		t.Fatalf("interface address + owner's community: device=%q basis=%q", ev.Device, ev.AttributionBasis)
	}
}

func TestReceiveOnlyNoDefaultOrForeignCommunityProvesAnything(t *testing.T) {
	t.Setenv("SNMP_COMMUNITY", "envcomm")
	r := roReceiver([]Target{acmeCtl("10.200.0.1", "acmecomm")}, nil)
	// public, the env default, the platform's (labcomm) and another tenant's.
	for _, comm := range []string{"public", "envcomm", "labcomm", "globexcomm", ""} {
		ev, err := r.decodePacket(buildV2cTrap(comm), "10.200.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if ev.Device != "" || ev.AttributionBasis != AttributionNone {
			t.Fatalf("community %q proved a controller-only device: device=%q basis=%q", comm, ev.Device, ev.AttributionBasis)
		}
	}
	// A receive-only target with NO community never falls back to a default.
	r = roReceiver([]Target{acmeCtl("10.200.0.1", "")}, nil)
	for _, comm := range []string{"public", "envcomm"} {
		ev, err := r.decodePacket(buildV2cTrap(comm), "10.200.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if ev.Device != "" {
			t.Fatalf("an empty receive-only community was satisfied by %q", comm)
		}
	}
	// A target not marked ReceiveOnly is dropped from the receive-only list
	// (it would otherwise be trusted with the default community).
	unmarked := acmeCtl("10.200.0.1", "")
	unmarked.ReceiveOnly = false
	r = roReceiver([]Target{unmarked}, nil)
	ev, err := r.decodePacket(buildV2cTrap("envcomm"), "10.200.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "" {
		t.Fatalf("an unmarked target in the receive-only list was trusted: %q", ev.Device)
	}
}

func TestReceiveOnlySharedAddressNamesNobody(t *testing.T) {
	other := Target{ID: "ctl-vmanage-acme2", Name: "acme-branch-10", Address: "10.200.0.1", TenantID: "acme",
		Community: "acmecomm", ReceiveOnly: true}
	r := roReceiver([]Target{acmeCtl("10.200.0.1", "acmecomm"), other}, nil)
	ev, err := r.decodePacket(buildV2cTrap("acmecomm"), "10.200.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "" {
		t.Fatalf("an address two controller-only devices hold named %q", ev.Device)
	}
	// The address of a DIRECT device: the direct rung answers or refuses; a
	// controller-only device never takes it, even with its own community.
	r = roReceiver([]Target{acmeCtl("192.168.222.106", "acmecomm")}, nil)
	ev, err = r.decodePacket(buildV2cTrap("acmecomm"), "192.168.222.106")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "" {
		t.Fatalf("a controller-only device took a direct device's address: %q", ev.Device)
	}
}

func TestReceiveOnlyDirectDeviceStands(t *testing.T) {
	// A trap that proves the DIRECT device keeps its attribution: the receive-only
	// rungs run only when every direct rung found nothing.
	r := roReceiver([]Target{acmeCtl("10.200.0.1", "labcomm")},
		map[string][]string{"192.168.200.33": {"cedge-81-11060ae2"}})
	ev, err := r.decodePacket(buildV2cTrap("labcomm"), "192.168.200.33")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "cedge-81-11060ae2" || ev.AttributionBasis != AttributionInterfaceIP {
		t.Fatalf("the direct device lost its trap: device=%q basis=%q", ev.Device, ev.AttributionBasis)
	}
	// A controller-only device named like a direct device never takes the name.
	named := acmeCtl("10.200.0.1", "acmecomm")
	named.Name = "cEDGE-40"
	r = roReceiver([]Target{named}, nil)
	ev, err = r.decodePacket(buildV2cSysNameTrap("acmecomm", "cEDGE-40"), "203.0.113.200")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "" {
		t.Fatalf("a direct device's name went to a controller-only device: %q", ev.Device)
	}
}

func TestReceiveOnlySysNameRescueBehindNAT(t *testing.T) {
	r := roReceiver([]Target{acmeCtl("10.200.0.1", "acmecomm")}, nil)
	ev, err := r.decodePacket(buildV2cSysNameTrap("acmecomm", "acme-branch-9"), "203.0.113.200")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "ctl-vmanage-acme1" || ev.AttributionBasis != AttributionSysName {
		t.Fatalf("sysName + owner's community from a NAT address: device=%q basis=%q", ev.Device, ev.AttributionBasis)
	}
	ev, err = r.decodePacket(buildV2cSysNameTrap("labcomm", "acme-branch-9"), "203.0.113.200")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "" {
		t.Fatalf("a forged sysName with another owner's community was accepted: %q", ev.Device)
	}
}

// v3: only an HMAC verified with this device's OWN candidate profile proves it.
func TestReceiveOnlyV3HMAC(t *testing.T) {
	good := snmpCreds{Version: 3, User: "acmeuser", Level: "authNoPriv", AuthProto: "SHA", AuthKey: "acmeauthkey123"}
	pkt := buildV3TrapForTest(t, good)
	other := Target{ID: "ctl-vmanage-acme1", Name: "acme-branch-9", Address: "10.200.0.1", TenantID: "acme",
		SNMPVersion: 3, V3User: "acmeuser", V3Level: "authNoPriv", V3AuthProto: "SHA", V3AuthKey: "notthekey456", ReceiveOnly: true}
	match := other
	match.V3AuthKey = good.AuthKey
	// The owner has two v3 profiles; the second is the one the device uses.
	r := roReceiver([]Target{other, match}, nil)
	ev, err := r.decodePacket(pkt, "10.200.0.1")
	if err != nil {
		t.Fatalf("v3 from a controller-only device: %v", err)
	}
	if !ev.Authenticated || ev.Device != "ctl-vmanage-acme1" || ev.AttributionBasis != AttributionMgmtIP {
		t.Fatalf("authenticated=%v device=%q basis=%q", ev.Authenticated, ev.Device, ev.AttributionBasis)
	}
	// A tampered trap verifies with no candidate: the original outcome stands
	// (an unknown sender, kept as evidence) — a guessed profile never refuses it.
	bad := append([]byte(nil), pkt...)
	bad[len(bad)-1] ^= 0xff
	ev, err = r.decodePacket(bad, "10.200.0.1")
	if err != nil && !strings.Contains(err.Error(), "snmptrap") {
		t.Fatalf("unexpected error: %v", err)
	}
	if err == nil && (ev.Authenticated || ev.Device != "") {
		t.Fatalf("a tampered v3 trap was attributed: authenticated=%v device=%q", ev.Authenticated, ev.Device)
	}
	// noAuthNoPriv proves nothing about a device nobody polls.
	none := match
	none.V3Level, none.V3AuthKey, none.V3AuthProto = "noAuthNoPriv", "", ""
	open := snmpCreds{Version: 3, User: "acmeuser", Level: "noAuthNoPriv"}
	r = roReceiver([]Target{none}, nil)
	ev, err = r.decodePacket(buildV3TrapForTest(t, open), "10.200.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "" {
		t.Fatalf("a noAuthNoPriv trap proved a controller-only device: %q", ev.Device)
	}
}

func TestReceiveOnlyTargetsNeverReachThePollers(t *testing.T) {
	direct := labTargets()
	p := NewPool(func() []Target { return direct })
	p.SetTrapReceiveOnlyTargets(func() []Target { return []Target{acmeCtl("10.200.0.1", "acmecomm")} })
	r, ok := p.collectors["snmptrap"].(*trapReceiver)
	if !ok {
		t.Fatal("no trap receiver in the pool")
	}
	for _, tg := range r.targets() {
		if tg.ReceiveOnly {
			t.Fatalf("a receive-only target reached the pool's TargetFunc: %+v", tg)
		}
	}
	if len(r.receiveOnly()) != 1 {
		t.Fatal("the receive-only target did not reach the trap receiver")
	}
}
