// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// lenIdx encodes a length-prefixed string index component plus trailing arcs.
func lenIdx(s string, trailing ...int) string {
	parts := []string{strconv.Itoa(len(s))}
	for _, c := range []byte(s) {
		parts = append(parts, strconv.Itoa(int(c)))
	}
	for _, t := range trailing {
		parts = append(parts, strconv.Itoa(t))
	}
	return strings.Join(parts, ".")
}

// impliedIdx encodes the same string WITHOUT the length octet.
func impliedIdx(s string, trailing ...int) string {
	parts := []string{}
	for _, c := range []byte(s) {
		parts = append(parts, strconv.Itoa(int(c)))
	}
	for _, t := range trailing {
		parts = append(parts, strconv.Itoa(t))
	}
	return strings.Join(parts, ".")
}

var vrfLim = vrfLimits{maxInstances: 100, maxMembers: 100}

func envFor(m *fakeMIB, names map[string]string) vrfEnv {
	return vrfEnv{walk: m.walk, addr: "x", creds: v2c("c"), lim: vrfLim, ifNames: func() map[string]string { return names }}
}

func members(r *vrfReading, vrf string) string {
	var out []string
	for i := range r.Members[vrf] {
		out = append(out, i)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// ── pure index / RD / name parsing ───────────────────────────────────────────

func TestSplitLenStringBothEncodingsAndHostileArcs(t *testing.T) {
	a, _ := parseArcs(lenIdx("CUST-A", 7))
	if n, rest, ok := splitLenString(a, 1); !ok || n != "CUST-A" || len(rest) != 1 || rest[0] != 7 {
		t.Fatalf("length-prefixed: %q %v %v", n, rest, ok)
	}
	a, _ = parseArcs(impliedIdx("CUST-A", 7))
	if n, _, ok := splitLenString(a, 1); !ok || n != "CUST-A" {
		t.Fatalf("implied fallback: %q %v", n, ok)
	}
	for _, idx := range []string{
		"3.65.66.300", // arc > 255
		"2.10.13",     // control characters
		"",            // empty
		"40.65.66",    // lying length, and too short for the fallback to be printable? (65,66 are printable → "AB" via fallback is fine)
	} {
		a, ok := parseArcs(idx)
		if !ok {
			continue
		}
		if n, _, ok := splitLenString(a, 0); ok && (strings.ContainsAny(n, "\r\n\t") || len(n) == 0) {
			t.Errorf("%q decoded to %q", idx, n)
		}
	}
	if _, ok := vrfName(strings.Repeat("a", maxVRFNameLen+1)); ok {
		t.Error("over-long name accepted")
	}
	if _, ok := vrfName("a\"b"); !ok {
		t.Error("a quote is printable and is escaped at emission; it must not be rejected")
	}
}

func TestRenderRD(t *testing.T) {
	for _, c := range []struct {
		raw  []byte
		want string
	}{
		{[]byte{0, 0, 0xfd, 0xe8, 0, 0, 0, 100}, "65000:100"}, // type 0
		{[]byte{0, 1, 10, 0, 0, 1, 0, 7}, "10.0.0.1:7"},       // type 1
		{[]byte{0, 2, 0, 1, 0xd4, 0xc0, 0, 5}, "120000:5"},    // type 2
		{[]byte("65001:20"), "65001:20"},                      // ASCII, also 8 octets
		{[]byte(" 65002:30 "), "65002:30"},                    // ASCII, padded
		{[]byte{0, 9, 1, 2, 3, 4, 5, 6}, ""},                  // unknown type: never a hex dump
		{[]byte{0xff, 0x01}, ""},                              // binary junk
		{nil, ""},
	} {
		if got := renderRD(c.raw); got != c.want {
			t.Errorf("renderRD(%v) = %q want %q", c.raw, got, c.want)
		}
	}
}

// ── per-vendor readers ──────────────────────────────────────────────────────

func TestRFC4382InstancesRDAndMembership(t *testing.T) {
	m := newFakeMIB()
	m.set(oidPlus(l3vpnVrfEntry, 6), lenIdx("CUST-A"), intVal(1))
	m.set(oidPlus(l3vpnVrfEntry, 6), lenIdx("CUST-B"), intVal(2))
	m.set(oidPlus(l3vpnVrfEntry, 4), lenIdx("CUST-A"), berVal{tag: 0x04, raw: []byte{0, 0, 0xfd, 0xe8, 0, 0, 0, 100}})
	m.set(oidPlus(l3vpnIfConf, 2), lenIdx("CUST-A", 3), intVal(2))
	m.set(oidPlus(l3vpnIfConf, 2), lenIdx("CUST-A", 4), intVal(2))
	m.set(oidPlus(l3vpnIfConf, 2), lenIdx("CUST-B", 99), intVal(2)) // ifIndex IF-MIB does not name
	r, err := srcL3VPN.read(context.Background(), envFor(m, map[string]string{"3": "Gi0/0/1", "4": "Gi0/0/2"}))
	if err != nil || r == nil {
		t.Fatalf("%v %v", r, err)
	}
	if len(r.Instances) != 2 || r.Instances["CUST-A"].RD != "65000:100" || r.Instances["CUST-A"].Oper != 1 || r.Instances["CUST-B"].Oper != 2 {
		t.Fatalf("%+v", r.Instances)
	}
	if got := members(r, "CUST-A"); got != "Gi0/0/1,Gi0/0/2" {
		t.Errorf("members = %q", got)
	}
	if members(r, "CUST-B") != "" || r.Dropped != 1 {
		t.Errorf("unnamed ifIndex must be dropped and counted: %q dropped=%d", members(r, "CUST-B"), r.Dropped)
	}
	if r.Instances["CUST-A"].Kind != "vrf" {
		t.Errorf("kind %q", r.Instances["CUST-A"].Kind)
	}
}

// The draft MIB numbers its IfConf columns differently (.3 not .2): reading
// the RFC column there must find nothing, reading .3 must find the member.
func TestDraftMPLSVPNUsesItsOwnColumn(t *testing.T) {
	m := newFakeMIB()
	m.set(oidPlus(mplsVpnVrfEntry, 6), lenIdx("RED"), intVal(1))
	m.set(oidPlus(mplsVpnIfConf, 3), lenIdx("RED", 5), intVal(2))
	m.set(oidPlus(mplsVpnIfConf, 2), lenIdx("RED", 6), intVal(2)) // the RFC column number: not membership here
	r, _ := srcMPLSVPN.read(context.Background(), envFor(m, map[string]string{"5": "Gi1", "6": "Gi2"}))
	if r == nil || members(r, "RED") != "Gi1" {
		t.Fatalf("%+v", r)
	}
}

func TestCiscoVRFMIBJoinsOnVrfIndex(t *testing.T) {
	m := newFakeMIB()
	m.set(oidPlus(ciscoVrfEntry, 2), "7", strVal("MGMT"))
	m.set(oidPlus(ciscoVrfEntry, 4), "7", intVal(1))
	m.set(oidPlus(ciscoVrfIfEntry, 2), "7.12", intVal(3))
	m.set(oidPlus(ciscoVrfIfEntry, 2), "8.12", intVal(3)) // unknown vrf index
	r, _ := srcCisco.read(context.Background(), envFor(m, map[string]string{"12": "Mgmt0"}))
	if r == nil || members(r, "MGMT") != "Mgmt0" || r.Instances["MGMT"].Oper != 1 || r.Dropped != 1 {
		t.Fatalf("%+v dropped=%d", r, r.Dropped)
	}
}

func TestJuniperKeepsOnlyL3VRFsAndDropsUnresolvedIfIndex(t *testing.T) {
	m := newFakeMIB()
	m.set(oidPlus(jnxVpnEntry, 3), "2."+lenIdx("BLUE"), intVal(1))
	m.set(oidPlus(jnxVpnEntry, 3), "4."+lenIdx("VPLS-1"), intVal(1)) // bgpVpls: not a routing instance here
	m.set(oidPlus(jnxVpnEntry, 7), "2."+lenIdx("BLUE"), berVal{tag: 0x04, raw: []byte{0, 1, 192, 0, 2, 1, 0, 9}})
	m.set(oidPlus(jnxVpnIfEntry, 10), "2."+lenIdx("BLUE", 501), intVal(5))
	m.set(oidPlus(jnxVpnIfEntry, 10), "2."+lenIdx("BLUE", 9999), intVal(5))
	r, _ := srcJuniper.read(context.Background(), envFor(m, map[string]string{"501": "ge-0/0/1.0"}))
	if r == nil || len(r.Instances) != 1 || r.Instances["BLUE"].RD != "192.0.2.1:9" || r.Instances["BLUE"].Kind != "routing-instance" {
		t.Fatalf("%+v", r)
	}
	if members(r, "BLUE") != "ge-0/0/1.0" || r.Dropped != 1 {
		t.Fatalf("members %q dropped %d", members(r, "BLUE"), r.Dropped)
	}
}

func TestAristaNameIsTheValue(t *testing.T) {
	m := newFakeMIB()
	m.set(oidPlus(aristaVrfEntry, 4), lenIdx("PROD"), intVal(1))
	m.set(oidPlus(aristaVrfEntry, 3), lenIdx("PROD"), strVal("65000:1"))
	m.set(oidPlus(aristaVrfIfEntry, 1), "1000001", strVal("PROD"))
	m.set(oidPlus(aristaVrfIfEntry, 1), "1000002", strVal("bad\nname"))
	r, _ := srcArista.read(context.Background(), envFor(m, map[string]string{"1000001": "Ethernet1", "1000002": "Ethernet2"}))
	if r == nil || r.Instances["PROD"].RD != "65000:1" || members(r, "PROD") != "Ethernet1" || r.Dropped != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestNokiaSkipsBaseRouterAndKeepsVPRNandVR(t *testing.T) {
	m := newFakeMIB()
	m.set(oidPlus(vRtrConfEntry, 28), "1", intVal(1)) // Base
	m.set(oidPlus(vRtrConfEntry, 4), "1", strVal("Base"))
	m.set(oidPlus(vRtrConfEntry, 28), "3", intVal(2))
	m.set(oidPlus(vRtrConfEntry, 4), "3", strVal("vprn100"))
	m.set(oidPlus(vRtrConfEntry, 28), "4", intVal(3))
	m.set(oidPlus(vRtrConfEntry, 4), "4", strVal("mgmt-vr"))
	m.set(oidPlus(vRtrStatEntry, 1), "3", intVal(2)) // inService
	m.set(oidPlus(vRtrIfEntry, 4), "3.2", strVal("to-ce1"))
	m.set(oidPlus(vRtrIfEntry, 4), "1.1", strVal("system"))
	r, _ := srcNokia.read(context.Background(), envFor(m, nil))
	if r == nil || len(r.Instances) != 2 || r.Instances["Base"] != nil {
		t.Fatalf("%+v", r)
	}
	if r.Instances["vprn100"].Kind != "vprn" || r.Instances["mgmt-vr"].Kind != "vr" || r.Instances["vprn100"].Oper != 1 {
		t.Fatalf("%+v %+v", r.Instances["vprn100"], r.Instances["mgmt-vr"])
	}
	if members(r, "vprn100") != "to-ce1" {
		t.Fatalf("members %q", members(r, "vprn100"))
	}
}

func TestViptelaVPNsFromInterfaceTableDedupAF(t *testing.T) {
	m := newFakeMIB()
	m.set(oidPlus(viptelaIfEntry, 11), "0."+lenIdx("ge0/0", 0), intVal(1))
	m.set(oidPlus(viptelaIfEntry, 11), "0."+lenIdx("ge0/0", 1), intVal(1)) // same interface, IPv6
	m.set(oidPlus(viptelaIfEntry, 11), "512."+lenIdx("eth0", 0), intVal(2))
	m.set(oidPlus(viptelaIfEntry, 11), "10."+lenIdx("ge0/2", 0), intVal(3))
	m.set(oidPlus(viptelaIfEntry, 11), "70000."+lenIdx("ge0/3", 0), intVal(4)) // VpnIndex out of range
	r, _ := srcViptela.read(context.Background(), envFor(m, nil))
	if r == nil || len(r.Instances) != 3 || r.Instances["10"].Kind != "vpn" || r.Dropped != 1 {
		t.Fatalf("%+v dropped=%d", r, r.Dropped)
	}
	if members(r, "0") != "ge0/0" || members(r, "512") != "eth0" || members(r, "10") != "ge0/2" {
		t.Fatalf("%v", r.Members)
	}
}

// ── order, capability and emission ──────────────────────────────────────────

func TestVendorOrderAndFirstAnswerWins(t *testing.T) {
	names := func(ss []vrfSource) string {
		var o []string
		for _, s := range ss {
			o = append(o, s.name)
		}
		return strings.Join(o, ",")
	}
	for ent, want := range map[int]string{
		9:     "mpls-l3vpn,mpls-vpn,cisco-vrf",
		2636:  "juniper-vpn,mpls-l3vpn,mpls-vpn",
		30065: "arista-vrf,mpls-l3vpn",
		6527:  "nokia-vrtr",
		41916: "viptela-vpn",
		2011:  "mpls-l3vpn,mpls-vpn", // Huawei: the standard
	} {
		if got := names(vrfSourcesFor(ent, true)); got != want {
			t.Errorf("enterprise %d: %s want %s", ent, got, want)
		}
	}
	// A Cisco box answering both RFC 4382 and CISCO-VRF-MIB is read ONCE.
	m := newFakeMIB()
	m.set(oidPlus(l3vpnVrfEntry, 6), lenIdx("A"), intVal(1))
	m.set(oidPlus(ciscoVrfEntry, 2), "1", strVal("A"))
	r, _ := readVRFs(context.Background(), vrfSourcesFor(9, true), envFor(m, nil))
	if r == nil || r.Source != vrfSrcL3VPN {
		t.Fatalf("%+v", r)
	}
	for _, w := range m.walks {
		if strings.HasPrefix(w, oidStr(ciscoVrfEntry)) {
			t.Errorf("a later source was walked after the first answered: %s", w)
		}
	}
}

func TestEmissionIsEscapedAndCarriesSource(t *testing.T) {
	r := newVRFReading(vrfSrcL3VPN)
	r.instance(`we"ird`).RD = "65000:1"
	r.member(`we"ird`, "Gi0/1")
	r.Truncated = true
	lines := strings.Join(vrfLines("dev-1", r, 5), "\n")
	for _, want := range []string{
		`device_vrf_info{device="dev-1",vrf="we\"ird",kind="vrf",rd="65000:1",source="mpls-l3vpn"} 1 5`,
		`device_vrf_if_info{device="dev-1",vrf="we\"ird",ifName="Gi0/1",source="mpls-l3vpn"} 1 5`,
		`collector_vrf_walk_truncated{device="dev-1"} 1 5`,
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("missing %s\n%s", want, lines)
		}
	}
	if strings.Contains(lines, "device_vrf_oper_status") {
		t.Error("oper status emitted for a source that did not report one")
	}
}

func TestCapabilityNeverSaysNoVRFsForASilentDevice(t *testing.T) {
	if got := (vrfResult{answered: false, err: "timeout"}).capability(); got != "not_answering" {
		t.Error(got)
	}
	if got := (vrfResult{answered: true}).capability(); got != "no_instances" {
		t.Error(got)
	}
	if got := (vrfResult{answered: true, err: "request timeout"}).capability(); got != "walk_failed" {
		t.Error("an agent that answered but whose walk failed is not 'not answering':", got)
	}
	if got := (vrfResult{answered: true, reading: newVRFReading(vrfSrcArista)}).capability(); got != vrfSrcArista {
		t.Error(got)
	}
}

// Walks happen on the refresh cadence; between them the cached reading is
// re-emitted so the series never go stale; a removed device is forgotten.
func TestPollDeviceCachesUntilRefresh(t *testing.T) {
	m := newFakeMIB()
	m.set(oidPlus(l3vpnVrfEntry, 6), lenIdx("A"), intVal(1))
	clock := time.Unix(1000, 0)
	gets := 0
	c := NewVRFInstances(nil).(*vrfCollector)
	c.walk = m.walk
	c.ifNames = func(context.Context, string, snmpCreds) map[string]string { return map[string]string{} }
	c.get = func(context.Context, string, snmpCreds, []int) (berVal, error) {
		gets++
		return berVal{tag: 0x06, raw: []byte{0x2b, 6, 1, 4, 1, 9, 1, 1}}, nil // 1.3.6.1.4.1.9.1.1
	}
	c.now = func() time.Time { return clock }
	tg := Target{ID: "r1", Address: "192.0.2.1"}
	if r := c.pollDevice(context.Background(), tg); r.reading == nil {
		t.Fatal("first poll must walk")
	}
	clock = clock.Add(5 * time.Minute)
	c.pollDevice(context.Background(), tg)
	if gets != 1 {
		t.Fatalf("walked again before refresh: %d", gets)
	}
	clock = clock.Add(6 * time.Minute)
	c.pollDevice(context.Background(), tg)
	if gets != 2 {
		t.Fatalf("not re-walked after refresh: %d", gets)
	}
	c.forgetGone(nil)
	if len(c.cache) != 0 || len(c.walked) != 0 || len(c.source) != 0 {
		t.Fatal("state for a removed device was kept")
	}
	// An unreachable device is reported, not cached as "no VRFs".
	c.get = func(context.Context, string, snmpCreds, []int) (berVal, error) {
		return berVal{}, errors.New("timeout")
	}
	if r := c.pollDevice(context.Background(), Target{ID: "r2", Address: "192.0.2.2"}); r.capability() != "not_answering" {
		t.Fatal(r.capability())
	}
}
