// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// Trap interface naming (tracker 387 PR 13c): an IF-MIB linkDown carries only
// ifIndex.N; the receiver names N through the ATTRIBUTED device's own ifIndex
// map. Varbinds are never rewritten.

import "testing"

// buildLinkDown is an IETF-format linkDown: ifIndex.N, ifAdminStatus.N,
// ifOperStatus.N, plus any extra varbinds.
func buildLinkDown(community string, idx int, extra ...[]byte) []byte {
	vb := func(oid []int, val []byte) []byte { return berTLV(0x30, append(berOID(oid), val...)) }
	vbs := vb([]int{1, 3, 6, 1, 2, 1, 1, 3, 0}, berTLV(0x43, []byte{0x00, 0x01, 0x00, 0x00}))
	vbs = append(vbs, vb([]int{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}, berOID([]int{1, 3, 6, 1, 6, 3, 1, 1, 5, 3}))...)
	vbs = append(vbs, vb([]int{1, 3, 6, 1, 2, 1, 2, 2, 1, 1, idx}, berInt(idx))...)
	vbs = append(vbs, vb([]int{1, 3, 6, 1, 2, 1, 2, 2, 1, 7, idx}, berInt(1))...)
	vbs = append(vbs, vb([]int{1, 3, 6, 1, 2, 1, 2, 2, 1, 8, idx}, berInt(2))...)
	for _, e := range extra {
		vbs = append(vbs, e...)
	}
	pduBody := berInt(42)
	pduBody = append(pduBody, berInt(0)...)
	pduBody = append(pduBody, berInt(0)...)
	pduBody = append(pduBody, berTLV(0x30, vbs)...)
	msg := berInt(1)
	msg = append(msg, berTLV(0x04, []byte(community))...)
	msg = append(msg, berTLV(0xA7, pduBody)...)
	return berTLV(0x30, msg)
}

func vedgeReceiver(maps map[string]map[string]string) *trapReceiver {
	ts := []Target{
		{ID: "vedge-20-1e95f00f", Address: "10.70.245.104", Community: "labcomm"},
		{ID: "vedge-51-aa", Address: "10.70.245.101", Community: "labcomm"},
	}
	r := &trapReceiver{targets: func() []Target { return ts }}
	r.SetIfNameResolver(func(dev, idx string) (string, bool) {
		n, ok := maps[dev][idx]
		return n, ok
	})
	return r
}

func TestTrapInterfaceFromIfIndexMap(t *testing.T) {
	r := vedgeReceiver(map[string]map[string]string{"vedge-20-1e95f00f": {"1": "ge0/0", "4": "ge0/3"}})
	ev, err := r.decodePacket(buildLinkDown("labcomm", 4), "10.70.245.104")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Interface != "ge0/3" || ev.InterfaceIndex != "4" || ev.InterfaceBasis != InterfaceIfIndexMap {
		t.Fatalf("interface=%q ifindex=%q basis=%q, want ge0/3/4/ifindex_map", ev.Interface, ev.InterfaceIndex, ev.InterfaceBasis)
	}
	// The varbinds the engine reads are untouched.
	found := false
	for _, vb := range ev.Varbinds {
		if vb.OID == "1.3.6.1.2.1.2.2.1.1.4" && vb.Value == "4" {
			found = true
		}
	}
	if !found {
		t.Error("the ifIndex varbind was rewritten")
	}
}

func TestTrapInterfaceMissStaysNumeric(t *testing.T) {
	r := vedgeReceiver(map[string]map[string]string{"vedge-20-1e95f00f": {"1": "ge0/0"}})
	ev, err := r.decodePacket(buildLinkDown("labcomm", 4), "10.70.245.104")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Interface != "4" || ev.InterfaceIndex != "4" || ev.InterfaceBasis != InterfaceIfIndexOnly {
		t.Fatalf("interface=%q ifindex=%q basis=%q, want 4/4/ifindex_only", ev.Interface, ev.InterfaceIndex, ev.InterfaceBasis)
	}
	// No lookup installed: numbers only, same basis.
	ts := []Target{{ID: "vedge-20-1e95f00f", Address: "10.70.245.104", Community: "labcomm"}}
	bare := &trapReceiver{targets: func() []Target { return ts }}
	ev, err = bare.decodePacket(buildLinkDown("labcomm", 4), "10.70.245.104")
	if err != nil {
		t.Fatal(err)
	}
	if ev.InterfaceBasis != InterfaceIfIndexOnly || ev.Interface != "4" {
		t.Fatalf("no resolver: interface=%q basis=%q", ev.Interface, ev.InterfaceBasis)
	}
}

// Device A's map must never name device B's index, and an unattributed trap's
// index is never named from anyone's map.
func TestTrapInterfaceNeverCrossesDevice(t *testing.T) {
	r := vedgeReceiver(map[string]map[string]string{"vedge-20-1e95f00f": {"4": "ge0/3"}})
	ev, err := r.decodePacket(buildLinkDown("labcomm", 4), "10.70.245.101") // vedge-51
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "vedge-51-aa" || ev.Interface == "ge0/3" || ev.InterfaceBasis != InterfaceIfIndexOnly {
		t.Fatalf("device=%q interface=%q basis=%q: vedge-20's name reached vedge-51", ev.Device, ev.Interface, ev.InterfaceBasis)
	}
	ev, err = r.decodePacket(buildLinkDown("wrong", 4), "10.70.245.104") // identity refused
	if err != nil {
		t.Fatal(err)
	}
	if ev.Device != "" || ev.Interface != "4" || ev.InterfaceBasis != InterfaceIfIndexOnly {
		t.Fatalf("unattributed trap named: device=%q interface=%q basis=%q", ev.Device, ev.Interface, ev.InterfaceBasis)
	}
}

// A trap that names the port itself wins: ifName in the varbinds, or a vendor
// object the MIB index resolves to *IfName (viptelaVpnIfName on Cisco SD-WAN).
func TestTrapInterfaceViptelaIfName(t *testing.T) {
	ev := &TrapEvent{Device: "vedge-20-1e95f00f", Varbinds: []TrapVarbind{
		{OID: "1.3.6.1.4.1.41916.100.1.67.0", Name: "viptelaVpnVpnId", Value: "0"},
		{OID: "1.3.6.1.4.1.41916.100.1.73.0", Name: "viptelaVpnIfName", Value: "ge0/1"},
	}}
	interfaceFor(ev, func(string, string) (string, bool) { return "WRONG", true })
	if ev.Interface != "ge0/1" || ev.InterfaceBasis != InterfaceVarbindName || ev.InterfaceIndex != "" {
		t.Fatalf("interface=%q ifindex=%q basis=%q", ev.Interface, ev.InterfaceIndex, ev.InterfaceBasis)
	}
	// IOS-XE's default linkDown carries ifName.N beside ifIndex.N.
	ifName := berTLV(0x30, append(berOID([]int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1, 3}), berTLV(0x04, []byte("Gi3"))...))
	r := vedgeReceiver(map[string]map[string]string{"vedge-20-1e95f00f": {"3": "map-name"}})
	got, err := r.decodePacket(buildLinkDown("labcomm", 3, ifName), "10.70.245.104")
	if err != nil {
		t.Fatal(err)
	}
	if got.Interface != "Gi3" || got.InterfaceIndex != "3" || got.InterfaceBasis != InterfaceVarbindName {
		t.Fatalf("ifName varbind: interface=%q ifindex=%q basis=%q", got.Interface, got.InterfaceIndex, got.InterfaceBasis)
	}
	none := &TrapEvent{Varbinds: []TrapVarbind{{OID: "1.3.6.1.2.1.1.3.0", Name: "sysUpTime", Value: "1"}}}
	interfaceFor(none, nil)
	if none.InterfaceBasis != InterfaceNone || none.Interface != "" {
		t.Fatalf("a trap about no interface: %+v", none)
	}
	// A suffix that is not one arc is not an index.
	if _, ok := ifIndexSuffix("1.3.6.1.2.1.2.2.1.1.4.1", oidIfIndexCol); ok {
		t.Error("a two-arc suffix read as an ifIndex")
	}
}
