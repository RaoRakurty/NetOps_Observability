// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ifbridge

import (
	"bytes"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

// cedge81 is the lab's cEDGE-81 interface list as vManage reports it
// (/dataservice/device/interface, read by the main session 2026-11-10).
func cedge81() []Row {
	return []Row{
		{IfIndex: "2", IfName: "GigabitEthernet2", VRF: "0", Addrs: []string{"192.1.6.2"}},
		{IfIndex: "8", IfName: "GigabitEthernet4.100", VRF: "0", Addrs: []string{"12.12.12.2"}},
		{IfIndex: "9", IfName: "GigabitEthernet4.200", VRF: "0", Addrs: []string{"14.14.14.2"}},
		{IfIndex: "12", IfName: "Sdwan-system-intf", VRF: "0", Addrs: []string{"10.255.255.81"}},
		{IfIndex: "1", IfName: "GigabitEthernet1", VRF: "100", Addrs: []string{"192.168.100.33"}},
		{IfIndex: "3", IfName: "GigabitEthernet3", VRF: "200", Addrs: []string{"192.168.200.33"}},
		{IfIndex: "7", IfName: "Loopback200", VRF: "200", Addrs: []string{"192.168.222.106"}},
		{IfIndex: "10", IfName: "Loopback65528", VRF: "65528", Addrs: []string{"192.168.1.1"}},
	}
}

func recs(dev, resolve string, at time.Time, rows ...Row) []Record {
	out := make([]Record, 0, len(rows))
	for _, r := range rows {
		out = append(out, Record{DeviceID: dev, Resolve: resolve, At: at, Row: r})
	}
	return out
}

func TestNormalizeSkipsInternalVPNAndUnidentifyingAddresses(t *testing.T) {
	cases := []struct {
		name    string
		in      Row
		ok      bool
		addrs   []string
		dropped int
	}{
		{"internal vpn by number", Row{IfName: "Loopback65528", VRF: "65528", Addrs: []string{"192.168.1.1"}}, false, nil, 0},
		{"internal vpn 65530, other name", Row{IfName: "loopback65531", VRF: "65530", Addrs: []string{"192.168.1.1/24"}}, false, nil, 0},
		{"internal loopback by name, no vpn", Row{IfName: "lo65529", Addrs: []string{"192.168.0.2"}}, false, nil, 0},
		{"vpn 65527 is a customer vpn", Row{IfName: "ge0/5", VRF: "65527", Addrs: []string{"10.1.1.1"}}, true, []string{"10.1.1.1"}, 0},
		{"prefix length stripped", Row{IfName: "ge0/0", VRF: "0", Addrs: []string{"200.20.2.20/24"}}, true, []string{"200.20.2.20"}, 0},
		{"unidentifying addresses dropped, row kept", Row{IfIndex: "11", IfName: "NVI0", Addrs: []string{"0.0.0.0", "127.0.0.1", "fe80::1", "224.0.0.5", "-", ""}}, true, nil, 6},
		{"ipv6 kept, canonical", Row{IfName: "ge0/1", Addrs: []string{"2001:DB8::0001/64"}}, true, []string{"2001:db8::1"}, 0},
		{"no name", Row{IfIndex: "4", Addrs: []string{"10.0.0.1"}}, false, nil, 0},
		{"duplicates collapse", Row{IfName: "Tunnel1", Addrs: []string{"10.0.0.1", "10.0.0.1/32"}}, true, []string{"10.0.0.1"}, 0},
	}
	for _, c := range cases {
		got, ok, dropped := Normalize(c.in)
		if ok != c.ok || dropped != c.dropped || (ok && !reflect.DeepEqual(got.Addrs, c.addrs)) {
			t.Errorf("%s: ok=%v dropped=%d addrs=%v, want ok=%v dropped=%d addrs=%v", c.name, ok, dropped, got.Addrs, c.ok, c.dropped, c.addrs)
		}
	}
}

func TestNormalizeIfIndexAndTextBounds(t *testing.T) {
	for in, want := range map[string]string{
		"4": "4", " 07 ": "7", "0": "", "4294967295": "", "abc": "", "null": "", "-1": "", "99999999999": "", "": "",
	} {
		if got, _, _ := Normalize(Row{IfName: "x", IfIndex: in}); got.IfIndex != want {
			t.Errorf("ifindex %q → %q, want %q", in, got.IfIndex, want)
		}
	}
	long := strings.Repeat("é", 300)
	got, ok, _ := Normalize(Row{IfName: "Gi1\x00\n", Alias: long, VRF: "200\t"})
	if !ok || got.IfName != "Gi1" || got.VRF != "200" || len([]rune(got.Alias)) != maxTextRunes {
		t.Fatalf("text not cleaned/bounded: %+v", got)
	}
	many := Row{IfName: "x"}
	for i := 0; i < MaxAddrsPerRow+5; i++ {
		many.Addrs = append(many.Addrs, net.IPv4(10, 0, 0, byte(i+1)).String())
	}
	if got, _, _ := Normalize(many); len(got.Addrs) != MaxAddrsPerRow {
		t.Fatalf("addresses not bounded: %d", len(got.Addrs))
	}
}

func TestIdentifyingAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"192.168.200.33": true, "10.255.255.81": true, "2001:db8::1": true,
		"127.0.0.1": false, "::1": false, "169.254.1.1": false, "fe80::1": false,
		"0.0.0.0": false, "::": false, "239.1.1.1": false, "ff02::1": false,
	} {
		if got := IdentifyingAddr(net.ParseIP(addr), "Gi1"); got != want {
			t.Errorf("%s: %v, want %v", addr, got, want)
		}
	}
	if IdentifyingAddr(net.ParseIP("192.168.1.1"), "Loopback65528") {
		t.Error("an internal VPN loopback named a device")
	}
	if IdentifyingAddr(nil, "Gi1") {
		t.Error("nil address named a device")
	}
}

func TestStoreIngestCountsWhatBridgesNothing(t *testing.T) {
	s := NewStore()
	in := recs("cedge-81", "matched", t0, cedge81()...)
	in = append(in, recs("", "no_match", t0, Row{IfName: "Gi1", Addrs: []string{"10.9.9.9"}})...)
	in = append(in, recs("", "ambiguous", t0, Row{IfName: "Gi1"})...)
	in = append(in, recs("", "conflict", t0, Row{IfName: "Gi2"})...)
	s.Ingest("global", "nmsi-1", "vmanage", in, t0)
	c := s.IngestCounts(t0)
	want := map[string]int{OutcomeInternalVPN: 1, OutcomeDeviceUnresolved: 1, OutcomeDeviceAmbiguous: 2}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("counts %v, want %v", c, want)
	}
	st, _ := s.Snapshot(map[string]string{"cedge-81": ""}, t0)
	d := st.Devices["cedge-81"]
	if d == nil || len(d.Rows) != 7 || d.Tenant != "global" || d.At != t0.UnixMilli() {
		t.Fatalf("snapshot %+v", d)
	}
	for _, r := range d.Rows {
		if r.VRF == "65528" {
			t.Fatalf("internal VPN row bridged: %+v", r)
		}
	}
	if len(s.IngestCounts(t0.Add(ingestCountsMaxAge+time.Second))) != 0 {
		t.Fatal("an integration that stopped polling kept its counts")
	}
	s.Ingest("global", "nmsi-1", "vmanage", in, t0)
	s.Forget("global", "nmsi-1")
	if len(s.IngestCounts(t0)) != 0 {
		t.Fatal("Forget kept the counts")
	}
}

// vEdge lists each interface once per address family; the rows fold into one.
func TestStoreFoldsAddressFamilyRows(t *testing.T) {
	s := NewStore()
	s.Ingest("global", "i", "vmanage", recs("vedge-20", "matched", t0,
		Row{IfIndex: "1", IfName: "ge0/0", VRF: "0", Addrs: []string{"200.20.2.20/24"}},
		Row{IfIndex: "1", IfName: "ge0/0", VRF: "0", Addrs: []string{"-"}},
		Row{IfIndex: "7", IfName: "eth0", VRF: "512", Alias: "OOB"},
		Row{IfName: "eth0", VRF: "512", Addrs: []string{"2001:db8::7"}},
	), t0)
	st, _ := s.Snapshot(map[string]string{"vedge-20": "global"}, t0)
	want := []Row{
		{IfIndex: "1", IfName: "ge0/0", VRF: "0", Addrs: []string{"200.20.2.20"}},
		{IfIndex: "7", IfName: "eth0", VRF: "512", Alias: "OOB", Addrs: []string{"2001:db8::7"}},
	}
	got := st.Devices["vedge-20"].Rows
	// mergeDuplicateRows sorts by name.
	if !reflect.DeepEqual(got, []Row{want[1], want[0]}) {
		t.Fatalf("rows %+v", got)
	}
}

func TestStoreNewerPollWinsAndReplaces(t *testing.T) {
	s := NewStore()
	s.Ingest("t_a", "int-1", "vmanage", recs("d1", "matched", t0, Row{IfIndex: "1", IfName: "Gi1"}, Row{IfIndex: "2", IfName: "Gi2"}), t0)
	// The same device from a second integration of the same owner, older.
	s.Ingest("t_a", "int-2", "vmanage", recs("d1", "matched", t0.Add(-time.Minute), Row{IfIndex: "1", IfName: "OLD"}), t0)
	st, _ := s.Snapshot(map[string]string{"d1": "t_a"}, t0)
	if r := st.Devices["d1"]; r.Integration != "int-1" || len(r.Rows) != 2 {
		t.Fatalf("an older poll replaced a newer one: %+v", r)
	}
	// A newer poll replaces the device's rows in full: Gi2 is gone.
	s.Ingest("t_a", "int-1", "vmanage", recs("d1", "matched", t0.Add(time.Minute), Row{IfIndex: "1", IfName: "Gi1"}), t0.Add(time.Minute))
	st, _ = s.Snapshot(map[string]string{"d1": "t_a"}, t0.Add(time.Minute))
	if r := st.Devices["d1"]; len(r.Rows) != 1 || r.Rows[0].IfName != "Gi1" {
		t.Fatalf("rows not replaced: %+v", r)
	}
	// A reading time from the future is the poll's own time.
	s.Ingest("t_a", "int-1", "vmanage", recs("d2", "matched", t0.Add(time.Hour), Row{IfName: "Gi1"}), t0)
	st, _ = s.Snapshot(map[string]string{"d2": "t_a"}, t0)
	if st.Devices["d2"].At != t0.UnixMilli() {
		t.Fatalf("future stamp kept: %d", st.Devices["d2"].At)
	}
}

func TestStoreBoundsRowsPerDevice(t *testing.T) {
	s := NewStore()
	var in []Record
	for i := 0; i < MaxRowsPerDevice+10; i++ {
		in = append(in, Record{DeviceID: "big", Resolve: "matched", At: t0, Row: Row{IfName: "port" + strconv.Itoa(i)}})
	}
	s.Ingest("global", "i", "vmanage", in, t0)
	if c := s.IngestCounts(t0)[OutcomeTruncated]; c != 10 {
		t.Fatalf("truncated %d, want 10", c)
	}
	st, _ := s.Snapshot(map[string]string{"big": ""}, t0)
	if n := len(st.Devices["big"].Rows); n != MaxRowsPerDevice {
		t.Fatalf("rows %d, want %d", n, MaxRowsPerDevice)
	}
}

// §3a: rows stand only under the owner they were resolved under. A device that
// left the inventory or changed owner loses them at once; they are never
// relabelled to the new owner.
func TestSnapshotDiscardsRowsOnOwnerChangeAndRemoval(t *testing.T) {
	s := NewStore()
	s.Ingest("t_acme", "i-a", "vmanage", recs("d1", "matched", t0, Row{IfName: "Gi1", Addrs: []string{"10.0.0.1"}}), t0)
	s.Ingest("global", "i-p", "vmanage", recs("d2", "matched", t0, Row{IfName: "Gi1", Addrs: []string{"10.0.0.2"}}), t0)
	st, _ := s.Snapshot(map[string]string{"d1": "t_globex", "d2": ""}, t0)
	if _, ok := st.Devices["d1"]; ok {
		t.Fatal("rows resolved under t_acme were published for a device t_globex owns")
	}
	if st.Devices["d2"] == nil {
		t.Fatal("platform rows ('global' integration, '' device owner) dropped")
	}
	// The discard is permanent: the device coming back to t_acme does not
	// resurrect rows that were dropped.
	st, _ = s.Snapshot(map[string]string{"d1": "t_acme", "d2": ""}, t0)
	if _, ok := st.Devices["d1"]; ok {
		t.Fatal("discarded rows came back")
	}
	st, _ = s.Snapshot(map[string]string{}, t0)
	if len(st.Devices) != 0 {
		t.Fatal("rows of devices no longer in inventory published")
	}
}

func TestSnapshotAgesRowsOutAtMaxAge(t *testing.T) {
	s := NewStore()
	s.Ingest("global", "i", "vmanage", recs("d1", "matched", t0, Row{IfName: "Gi1"}), t0)
	owners := map[string]string{"d1": ""}
	if st, stats := s.Snapshot(owners, t0.Add(MaxAge-time.Second)); st.Devices["d1"] == nil || stats.Stale != 0 {
		t.Fatal("rows aged out early")
	}
	st, stats := s.Snapshot(owners, t0.Add(MaxAge))
	if st.Devices["d1"] != nil || stats.Stale != 1 {
		t.Fatalf("rows not aged out at MaxAge: stale=%d", stats.Stale)
	}
}

func TestStateSanitize(t *testing.T) {
	st := State{Version: StateVersion, Devices: map[string]*DeviceRows{
		"ok":     {Tenant: "GLOBAL", At: t0.Add(-time.Hour).UnixMilli(), Rows: []Row{{IfName: "Gi1", Addrs: []string{"10.0.0.1", "127.0.0.1"}}}},
		"future": {At: t0.Add(time.Hour).UnixMilli(), Rows: []Row{{IfName: "Gi1"}}},
		"old":    {At: t0.Add(-MaxAge).UnixMilli(), Rows: []Row{{IfName: "Gi1"}}},
		"zero":   {Rows: []Row{{IfName: "Gi1"}}},
		"bad":    {At: t0.UnixMilli(), Rows: []Row{{IfName: "Lo65528", VRF: "65528"}}},
		"":       {At: t0.UnixMilli(), Rows: []Row{{IfName: "Gi1"}}},
		"nil":    nil,
	}}
	st.Sanitize(t0)
	if len(st.Devices) != 1 || st.Devices["ok"] == nil {
		t.Fatalf("sanitize kept %v", keys(st.Devices))
	}
	if d := st.Devices["ok"]; d.Tenant != "global" || !reflect.DeepEqual(d.Rows[0].Addrs, []string{"10.0.0.1"}) {
		t.Fatalf("row not re-validated: %+v", d)
	}
	other := State{Version: 99, Devices: map[string]*DeviceRows{"x": {At: t0.UnixMilli(), Rows: []Row{{IfName: "Gi1"}}}}}
	other.Sanitize(t0)
	if other.Version != StateVersion || len(other.Devices) != 0 {
		t.Fatal("another version was reinterpreted")
	}
}

func TestStoreLoadKeepsNewerMemory(t *testing.T) {
	s := NewStore()
	s.Ingest("global", "i", "vmanage", recs("d1", "matched", t0, Row{IfName: "NEW"}), t0)
	persisted := NewState()
	persisted.Devices["d1"] = &DeviceRows{Tenant: "global", At: t0.Add(-time.Hour).UnixMilli(), Rows: []Row{{IfName: "OLD"}}}
	persisted.Devices["d2"] = &DeviceRows{Tenant: "global", At: t0.Add(-time.Hour).UnixMilli(), Rows: []Row{{IfName: "KEPT"}}}
	s.Load(persisted, t0)
	st, _ := s.Snapshot(map[string]string{"d1": "", "d2": ""}, t0)
	if st.Devices["d1"].Rows[0].IfName != "NEW" || st.Devices["d2"].Rows[0].IfName != "KEPT" {
		t.Fatalf("load: %+v / %+v", st.Devices["d1"], st.Devices["d2"])
	}
}

func keys[V any](m map[string]V) []string { return sortedKeys(m) }

func nmsState(devs map[string]*DeviceRows) State {
	st := NewState()
	for k, v := range devs {
		st.Devices[k] = v
	}
	return st
}

// gi treats a short and a long IOS-XE spelling as one port, like the api's
// canonIface comparison.
func gi(a, b string) bool {
	n := func(s string) string {
		s = strings.ToLower(s)
		return strings.Replace(s, "gigabitethernet", "gi", 1)
	}
	return n(a) == n(b)
}

func TestMergeFillsADeviceSNMPCannotReach(t *testing.T) {
	snmp := SNMP{
		Addr:  map[string]map[string]string{"cedge-40": {"192.168.200.25": "Gi3"}},
		Index: map[string]map[string]string{"cedge-40": {"3": "Gi3"}},
	}
	s := NewStore()
	s.Ingest("global", "i", "vmanage", recs("cedge-81", "matched", t0, cedge81()...), t0)
	st, _ := s.Snapshot(map[string]string{"cedge-81": "", "cedge-40": ""}, t0)
	m := Merge(snmp, st, gi, map[string]string{"cedge-81": "", "cedge-40": ""})
	if m.Addr["cedge-81"]["192.168.200.33"] != "GigabitEthernet3" || m.AddrVRF["cedge-81"]["192.168.200.33"] != "200" {
		t.Fatalf("cedge-81 Gi3 not bridged with its VRF: %v %v", m.Addr["cedge-81"], m.AddrVRF["cedge-81"])
	}
	if _, ok := m.Addr["cedge-81"]["192.168.1.1"]; ok {
		t.Fatal("the shared internal loopback reached the bridge")
	}
	if m.Index["cedge-81"]["3"] != "GigabitEthernet3" || m.IndexSource["cedge-81"]["3"] != SourceNMS {
		t.Fatalf("ifIndex 3 not bridged from the NMS: %v", m.Index["cedge-81"])
	}
	if m.Addr["cedge-40"]["192.168.200.25"] != "Gi3" || m.AddrSource["cedge-40"]["192.168.200.25"] != SourceSNMP {
		t.Fatal("SNMP rows of another device changed")
	}
	if m.Stats[StatKey{SourceNMS, MergeBridged}] != 14 || m.Stats[StatKey{SourceSNMP, MergeBridged}] != 2 {
		t.Fatalf("stats %v", m.Stats)
	}
}

func TestMergeAgreementKeepsTheSNMPSpelling(t *testing.T) {
	snmp := SNMP{
		Addr:    map[string]map[string]string{"d": {"10.0.0.3": "Gi3"}},
		Index:   map[string]map[string]string{"d": {"3": "Gi3"}},
		IndexAt: map[string]int64{"d": t0.Add(-time.Hour).UnixMilli()},
		AddrAt:  map[string]int64{"d": t0.Add(-time.Hour).UnixMilli()},
	}
	st := nmsState(map[string]*DeviceRows{"d": {Tenant: "global", At: t0.UnixMilli(), Rows: []Row{
		{IfIndex: "3", IfName: "GigabitEthernet3", VRF: "200", Addrs: []string{"10.0.0.3"}},
	}}})
	m := Merge(snmp, st, gi, nil)
	if m.Index["d"]["3"] != "Gi3" || m.Addr["d"]["10.0.0.3"] != "Gi3" || m.IndexSource["d"]["3"] != SourceSNMP {
		t.Fatalf("agreement replaced the SNMP spelling: %v %v", m.Index, m.Addr)
	}
	if m.AddrVRF["d"]["10.0.0.3"] != "200" {
		t.Fatal("the VRF of an agreed address was lost")
	}
	if m.Stats[StatKey{SourceNMS, MergeAgreed}] != 2 || m.Stats[StatKey{SourceNMS, MergeConflictWon}] != 0 {
		t.Fatalf("stats %v", m.Stats)
	}
}

func TestMergeConflictNewestWinsBothWays(t *testing.T) {
	older, newer := t0.Add(-time.Hour).UnixMilli(), t0.UnixMilli()
	snmp := func(at int64) SNMP {
		return SNMP{
			Index:   map[string]map[string]string{"d": {"4": "ge0/3"}},
			Addr:    map[string]map[string]string{"d": {"10.0.0.4": "ge0/3"}},
			IndexAt: map[string]int64{"d": at}, AddrAt: map[string]int64{"d": at},
		}
	}
	st := nmsState(map[string]*DeviceRows{"d": {Tenant: "global", At: t0.Add(-30 * time.Minute).UnixMilli(), Rows: []Row{
		{IfIndex: "4", IfName: "ge0/4", Addrs: []string{"10.0.0.4"}},
	}}})
	m := Merge(snmp(older), st, nil, nil)
	if m.Index["d"]["4"] != "ge0/4" || m.Addr["d"]["10.0.0.4"] != "ge0/4" || m.IndexSource["d"]["4"] != SourceNMS || m.AddrSource["d"]["10.0.0.4"] != SourceNMS {
		t.Fatalf("newer NMS lost: %v %v", m.Index, m.Addr)
	}
	if m.Stats[StatKey{SourceNMS, MergeConflictWon}] != 2 || m.Stats[StatKey{SourceSNMP, MergeConflictLost}] != 2 {
		t.Fatalf("both sources not recorded: %v", m.Stats)
	}
	m = Merge(snmp(newer), st, nil, nil)
	if m.Index["d"]["4"] != "ge0/3" || m.Addr["d"]["10.0.0.4"] != "ge0/3" {
		t.Fatalf("newer SNMP lost: %v %v", m.Index, m.Addr)
	}
	if m.Stats[StatKey{SourceNMS, MergeConflictLost}] != 2 || m.Stats[StatKey{SourceSNMP, MergeConflictWon}] != 2 {
		t.Fatalf("both sources not recorded: %v", m.Stats)
	}
	if _, ok := m.AddrVRF["d"]["10.0.0.4"]; ok {
		t.Fatal("a losing NMS address kept a VRF")
	}
	// A tie is the device's own walk.
	m = Merge(snmp(t0.Add(-30*time.Minute).UnixMilli()), st, nil, nil)
	if m.Index["d"]["4"] != "ge0/3" {
		t.Fatal("a tie did not go to SNMP")
	}
	// An SNMP row of unknown age is older than any NMS reading.
	unknown := snmp(0)
	unknown.IndexAt, unknown.AddrAt = nil, nil
	if m = Merge(unknown, st, nil, nil); m.Index["d"]["4"] != "ge0/4" {
		t.Fatal("an SNMP row of unknown age beat a dated NMS reading")
	}
}

// An address two devices of one owner hold stays on both (the resolvers name
// neither) and is counted; the same address under two owners is not "shared"
// for this count (it is two tenants' address space).
func TestMergeSharedAddressStaysOnBoth(t *testing.T) {
	snmp := SNMP{Addr: map[string]map[string]string{"a": {"10.0.0.9": "Gi1"}}}
	st := nmsState(map[string]*DeviceRows{
		"b": {Tenant: "global", At: t0.UnixMilli(), Rows: []Row{{IfName: "Gi2", Addrs: []string{"10.0.0.9"}}}},
		"c": {Tenant: "t_acme", At: t0.UnixMilli(), Rows: []Row{{IfName: "Gi3", Addrs: []string{"10.0.0.9"}}}},
	})
	m := Merge(snmp, st, nil, map[string]string{"a": "", "b": "global", "c": "t_acme"})
	if m.Addr["a"]["10.0.0.9"] != "Gi1" || m.Addr["b"]["10.0.0.9"] != "Gi2" || m.Addr["c"]["10.0.0.9"] != "Gi3" {
		t.Fatalf("a shared address was settled: %v", m.Addr)
	}
	if m.Stats[StatKey{SourceSNMP, MergeSharedAddr}] != 1 || m.Stats[StatKey{SourceNMS, MergeSharedAddr}] != 1 {
		t.Fatalf("shared counts %v", m.Stats)
	}
}

func TestMergeAliases(t *testing.T) {
	snmp := SNMP{
		Index:   map[string]map[string]string{"d": {"1": "Gi1", "2": "Gi2"}},
		Alias:   map[string]map[string]string{"d": {"1": "WAN-to-ISP-A", "2": "old"}},
		IndexAt: map[string]int64{"d": t0.Add(-time.Hour).UnixMilli()},
	}
	st := nmsState(map[string]*DeviceRows{"d": {Tenant: "global", At: t0.UnixMilli(), Rows: []Row{
		{IfIndex: "2", IfName: "GigabitEthernet2", Alias: "new"},
		{IfIndex: "3", IfName: "GigabitEthernet3", Alias: "LAN"},
	}}})
	m := Merge(snmp, st, gi, nil)
	want := map[string]string{"1": "WAN-to-ISP-A", "2": "new", "3": "LAN"}
	if !reflect.DeepEqual(m.Alias["d"], want) {
		t.Fatalf("aliases %v, want %v", m.Alias["d"], want)
	}
}

func TestMergeEmptyIsEmpty(t *testing.T) {
	m := Merge(SNMP{}, NewState(), nil, nil)
	if len(m.Addr) != 0 || len(m.Index) != 0 || len(m.Stats) != 0 {
		t.Fatalf("empty merge produced %+v", m)
	}
}

func TestMetricsClosedLabelSetZeroFilled(t *testing.T) {
	m := NewMetrics()
	m.Set(map[StatKey]int{{SourceNMS, MergeBridged}: 14}, map[string]int{OutcomeDeviceUnresolved: 3}, SnapshotStats{Stale: 2, Truncated: 1})
	m.Published(1700000000)
	m.ReadFailed()
	var b bytes.Buffer
	m.WriteMetrics(&b)
	out := b.String()
	for _, line := range []string{
		`netops_nms_iface_bridge_rows{source="nms",outcome="bridged"} 14`,
		`netops_nms_iface_bridge_rows{source="nms",outcome="device_unresolved"} 3`,
		`netops_nms_iface_bridge_rows{source="nms",outcome="stale"} 2`,
		`netops_nms_iface_bridge_rows{source="nms",outcome="truncated"} 1`,
		`netops_nms_iface_bridge_rows{source="snmp",outcome="bridged"} 0`,
		`netops_nms_iface_bridge_failures_total{stage="read"} 1`,
		`netops_nms_iface_bridge_last_publish_timestamp_seconds 1700000000`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("missing %q in\n%s", line, out)
		}
	}
	if n := strings.Count(out, "netops_nms_iface_bridge_rows{"); n != len(metricPairs()) {
		t.Fatalf("%d series, want the closed set of %d", n, len(metricPairs()))
	}
	for _, bad := range []string{"tenant", "device", "integration"} {
		if strings.Contains(out, bad+"=") {
			t.Fatalf("label %q on a platform series", bad)
		}
	}
	if m.Rows(SourceNMS, MergeBridged) != 14 {
		t.Fatal("Rows")
	}
	var nilM *Metrics
	nilM.WriteMetrics(&b) // nil-safe
}
