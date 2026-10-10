// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"bufio"
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── an in-memory MIB: column OID → row index → value ─────────────────────────

type fakeMIB struct {
	mu     sync.Mutex
	cols   map[string]map[string]berVal
	failOn map[string]error // column → error
	walks  []string         // columns walked, in order
}

func newFakeMIB() *fakeMIB {
	return &fakeMIB{cols: map[string]map[string]berVal{}, failOn: map[string]error{}}
}

func (m *fakeMIB) set(colOID []int, idx string, v berVal) {
	k := oidStr(colOID)
	if m.cols[k] == nil {
		m.cols[k] = map[string]berVal{}
	}
	m.cols[k][idx] = v
}

func (m *fakeMIB) walk(_ context.Context, _ string, _ snmpCreds, colOID []int, maxRows int) (map[string]berVal, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := oidStr(colOID)
	m.walks = append(m.walks, k)
	if err := m.failOn[k]; err != nil {
		return nil, false, err
	}
	rows := m.cols[k]
	keys := make([]string, 0, len(rows))
	for r := range rows {
		keys = append(keys, r)
	}
	sort.Strings(keys)
	out := map[string]berVal{}
	for i, r := range keys {
		if i >= maxRows {
			return out, true, nil
		}
		out[r] = rows[r]
	}
	return out, false, nil
}

func oidStr(o []int) string {
	ss := make([]string, len(o))
	for i, a := range o {
		ss[i] = strconv.Itoa(a)
	}
	return strings.Join(ss, ".")
}

func intVal(n int64) berVal  { return berVal{tag: 0x02, raw: berInt(int(n))[2:]} }
func strVal(s string) berVal { return berVal{tag: 0x04, raw: []byte(s)} }
func ipVal(a, b, c, d byte) berVal {
	return berVal{tag: 0x40, raw: []byte{a, b, c, d}}
}

// bfdIdx builds a session row index in the LENGTH-PREFIXED form.
func bfdIdx(src, dst [4]int, proto int) string {
	p := []int{4, src[0], src[1], src[2], src[3], 4, dst[0], dst[1], dst[2], dst[3], proto, 12346, 12346}
	return oidStr(p)
}

func tlocIdx(name string, encap int) string {
	p := []int{len(name)}
	for _, c := range name {
		p = append(p, int(c))
	}
	return oidStr(append(p, encap))
}

// seedEdge loads one edge's identity, two TLOCs and a set of sessions into m
// under MIB family fam.
func seedEdge(m *fakeMIB, fam sdwanMIB, sysIP [4]byte, personality string) {
	m.set(col(fam.local, localSystemIP), "0", ipVal(sysIP[0], sysIP[1], sysIP[2], sysIP[3]))
	m.set(col(fam.local, localSiteID), "0", intVal(100))
	m.set(fam.personality, "0", strVal(personality))
	for _, t := range []struct {
		name         string
		total, up, f int64
	}{{"GigabitEthernet1", 4, 4, 0}, {"GigabitEthernet2", 4, 4, 1}} {
		m.set(col(fam.tlocEntry, tlocTotal), tlocIdx(t.name, 2), intVal(t.total))
		m.set(col(fam.tlocEntry, tlocUp), tlocIdx(t.name, 2), intVal(t.up))
		m.set(col(fam.tlocEntry, tlocFlap), tlocIdx(t.name, 2), intVal(t.f))
	}
}

// addSession adds one BFD session row.
func addSession(m *fakeMIB, fam sdwanMIB, src, dst [4]int, peerSys [4]byte, site, lcolor, rcolor, state int64) {
	idx := bfdIdx(src, dst, 2)
	m.set(col(fam.bfdEntry, bfdSystemIP), idx, ipVal(peerSys[0], peerSys[1], peerSys[2], peerSys[3]))
	m.set(col(fam.bfdEntry, bfdSiteID), idx, intVal(site))
	m.set(col(fam.bfdEntry, bfdLocalColor), idx, intVal(lcolor))
	m.set(col(fam.bfdEntry, bfdColor), idx, intVal(rcolor))
	m.set(col(fam.bfdEntry, bfdState), idx, intVal(state))
}

var lim = overlayLimits{maxSessionRows: 1000, maxTLOCRows: 64}

// ── index parsing ────────────────────────────────────────────────────────────

func TestParseBFDIndexBothEncodings(t *testing.T) {
	for _, c := range []struct {
		idx            string
		src, dst, prot string
	}{
		{"10.0.0.1.10.0.0.2.2.12346.12346", "10.0.0.1", "10.0.0.2", "ipsec"},   // fixed-size IPv4
		{"4.10.0.0.1.4.10.0.0.2.1.12346.12346", "10.0.0.1", "10.0.0.2", "gre"}, // length-prefixed
		{"4.4.4.4.4.4.4.4.2.12346.12346", "4.4.4.4", "4.4.4.4", "ipsec"},       // a 4.x address, fixed-size (11 arcs)
		{"4.4.4.4.4.4.4.4.4.4.2.12346.12346", "4.4.4.4", "4.4.4.4", "ipsec"},   // the same, length-prefixed (13 arcs)
	} {
		bi, ok := parseBFDIndex(c.idx)
		if !ok || bi.src != c.src || bi.dst != c.dst || bi.proto != c.prot {
			t.Errorf("%s → %+v ok=%v, want %s→%s %s", c.idx, bi, ok, c.src, c.dst, c.prot)
		}
	}
	for _, bad := range []string{"", "1.2.3", "5.10.0.0.1.4.10.0.0.2.1.1.1", "10.0.0.300.10.0.0.2.2.1.1", "a.b"} {
		if _, ok := parseBFDIndex(bad); ok {
			t.Errorf("%q parsed but should not", bad)
		}
	}
}

func TestParseTLOCIndex(t *testing.T) {
	if n, e, ok := parseTLOCIndex(tlocIdx("ge0/0", 2)); !ok || n != "ge0/0" || e != "ipsec" {
		t.Fatalf("prefixed: %q %q %v", n, e, ok)
	}
	// No length octet: every arc but the last is the name.
	if n, e, ok := parseTLOCIndex("103.101.48.47.49.1"); !ok || n != "ge0/1" || e != "gre" {
		t.Fatalf("unprefixed: %q %q %v", n, e, ok)
	}
	if _, _, ok := parseTLOCIndex("3.1.2.3.2"); ok {
		t.Fatal("non-printable interface name accepted")
	}
}

// ── the probe and the session fold ───────────────────────────────────────────

func TestProbeFindsTheRightMIBFamily(t *testing.T) {
	for _, fam := range sdwanMIBs {
		m := newFakeMIB()
		seedEdge(m, fam, [4]byte{10, 255, 0, 1}, "vedge")
		f, err := probeOverlay(context.Background(), m.walk, "x", v2c("c"), lim)
		if err != nil {
			t.Fatalf("%s: %v", fam.name, err)
		}
		if f.MIB != fam.name || f.Capability != OverlayAvailable || f.SystemIP != "10.255.0.1" ||
			f.Personality != "vedge" || f.SiteID != "100" || len(f.TLOCs) != 2 {
			t.Fatalf("%s: %+v", fam.name, f)
		}
		if f.TLOCs[1].Interface != "GigabitEthernet2" || f.TLOCs[1].Flaps != 1 || f.TLOCs[1].Encap != "ipsec" {
			t.Fatalf("%s TLOC: %+v", fam.name, f.TLOCs)
		}
	}
}

func TestProbeOnADeviceWithoutSDWANMIBs(t *testing.T) {
	m := newFakeMIB() // answers nothing under either family
	f, err := probeOverlay(context.Background(), m.walk, "x", v2c("c"), lim)
	if err != nil || f.Capability != OverlayNotAnswering || f.MIB != "" {
		t.Fatalf("got %+v err=%v", f, err)
	}
	// The probe costs two short walks per family, nothing more.
	if len(m.walks) != 4 {
		t.Fatalf("probe walked %d columns, want 4 (system-ip + TLOC total, per family)", len(m.walks))
	}
}

// Identity without the session tables (a view that exposes only part of the
// subtree) is partial, never available.
func TestProbePartialCapability(t *testing.T) {
	m := newFakeMIB()
	fam := sdwanMIBs[1]
	m.set(col(fam.local, localSystemIP), "0", ipVal(10, 255, 0, 9))
	f, _ := probeOverlay(context.Background(), m.walk, "x", v2c("c"), lim)
	if f.Capability != OverlayPartial || f.SystemIP != "10.255.0.9" {
		t.Fatalf("got %+v", f)
	}
}

func TestReadSessionsFoldsPerPeerAndColor(t *testing.T) {
	m := newFakeMIB()
	fam := sdwanMIBs[0]
	me := [4]int{198, 51, 100, 1}
	// Peer A over two colors (biz-internet ↔ biz-internet up, mpls ↔ mpls down),
	// plus a second biz-internet session to the same peer (another TLOC) that is up.
	addSession(m, fam, me, [4]int{198, 51, 100, 2}, [4]byte{10, 255, 0, 2}, 200, 4, 4, 3)
	addSession(m, fam, [4]int{192, 0, 2, 1}, [4]int{192, 0, 2, 2}, [4]byte{10, 255, 0, 2}, 200, 2, 2, 1)
	addSession(m, fam, [4]int{198, 51, 100, 9}, [4]int{198, 51, 100, 2}, [4]byte{10, 255, 0, 2}, 200, 4, 4, 3)
	// Peer B: everything down.
	addSession(m, fam, me, [4]int{198, 51, 100, 3}, [4]byte{10, 255, 0, 3}, 300, 4, 4, 1)
	peers, local, rows, trunc, err := readSessions(context.Background(), m.walk, "x", v2c("c"), fam.name, lim)
	if err != nil || trunc || rows != 4 || len(peers) != 2 {
		t.Fatalf("peers=%d rows=%d trunc=%v err=%v", len(peers), rows, trunc, err)
	}
	a, b := peers[0], peers[1]
	if a.SystemIP != "10.255.0.2" || a.SiteID != "200" || len(a.ColorPairs) != 2 {
		t.Fatalf("peer A: %+v", a)
	}
	biz := a.ColorPairs[0]
	if biz.LocalColor != "biz-internet" || biz.Sessions != 2 || biz.Up != 2 || biz.State != "up" || biz.Proto != "ipsec" {
		t.Fatalf("peer A biz-internet pair: %+v", biz)
	}
	if mp := a.ColorPairs[1]; mp.LocalColor != "mpls" || mp.State != "down" || mp.Up != 0 {
		t.Fatalf("peer A mpls pair: %+v", mp)
	}
	if !peerUp(a) || peerUp(b) {
		t.Fatalf("peerUp: A=%v B=%v", peerUp(a), peerUp(b))
	}
	// The endpoints that resolve system-ip ownership downstream.
	if strings.Join(a.TLOCAddrs, ",") != "192.0.2.2,198.51.100.2" || strings.Join(b.TLOCAddrs, ",") != "198.51.100.3" {
		t.Fatalf("peer TLOC addrs: A=%v B=%v", a.TLOCAddrs, b.TLOCAddrs)
	}
	if strings.Join(local, ",") != "192.0.2.1,198.51.100.1,198.51.100.9" {
		t.Fatalf("local TLOC addrs: %v", local)
	}
}

// Identity columns differ between releases (lab, 2026-10-10: a vEdge answered
// its site-id column with the vBond hostname, and no system-ip). A value of the
// wrong type is dropped, never published as identity.
func TestIdentityColumnsOfTheWrongTypeAreDropped(t *testing.T) {
	m := newFakeMIB()
	fam := sdwanMIBs[0]
	seedEdge(m, fam, [4]byte{10, 255, 0, 1}, "vedge")
	m.set(col(fam.local, localSiteID), "0", strVal("vbond.or2.sys.cisco"))
	m.set(col(fam.local, localSystemIP), "0", strVal("not-an-address"))
	f, _ := probeOverlay(context.Background(), m.walk, "x", v2c("c"), lim)
	if f.SiteID != "" || f.SystemIP != "" {
		t.Fatalf("wrong-typed identity published: site=%q system-ip=%q", f.SiteID, f.SystemIP)
	}
	// TLOCs still make the device worth walking.
	if f.MIB != fam.name || len(f.TLOCs) != 2 {
		t.Fatalf("%+v", f)
	}
}

// Sessions + transports make an edge available even when no identity column
// answered: the system-ip is resolved from the peers downstream.
func TestEdgeWithSessionsButNoSystemIPIsAvailable(t *testing.T) {
	m := newFakeMIB()
	fam := sdwanMIBs[0]
	seedEdge(m, fam, [4]byte{10, 255, 0, 1}, "vedge")
	m.set(col(fam.local, localSystemIP), "0", strVal("")) // answers, empty
	addSession(m, fam, [4]int{198, 51, 100, 1}, [4]int{198, 51, 100, 2}, [4]byte{10, 255, 0, 2}, 200, 4, 4, 3)
	pub := &publishLog{}
	c := newTestCollector(m, pub)
	r := c.pollDevice(context.Background(), Target{ID: "v", Address: "192.0.2.20"})
	if r.facts == nil || r.facts.Capability != OverlayAvailable || r.facts.SystemIP != "" ||
		strings.Join(r.facts.LocalTLOCAddrs, ",") != "198.51.100.1" {
		t.Fatalf("%+v", r.facts)
	}
}

// A walk that hits the row cap says so — the peers past it are unknown.
func TestReadSessionsReportsTruncation(t *testing.T) {
	m := newFakeMIB()
	fam := sdwanMIBs[1]
	for i := 2; i < 12; i++ {
		addSession(m, fam, [4]int{10, 1, 0, 1}, [4]int{10, 1, 0, i}, [4]byte{10, 255, 1, byte(i)}, int64(i), 4, 4, 3)
	}
	peers, _, _, trunc, err := readSessions(context.Background(), m.walk, "x", v2c("c"), fam.name, overlayLimits{maxSessionRows: 5, maxTLOCRows: 8})
	if err != nil || !trunc || len(peers) != 5 {
		t.Fatalf("peers=%d trunc=%v err=%v", len(peers), trunc, err)
	}
}

// ── the collector's per-device scheduling ───────────────────────────────────

type publishLog struct {
	mu   sync.Mutex
	got  []OverlayDeviceFacts
	fail error
}

func (p *publishLog) publish(_ context.Context, f OverlayDeviceFacts, _ time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.got = append(p.got, f)
	return p.fail
}

func newTestCollector(m *fakeMIB, pub *publishLog) *sdwanOverlayCollector {
	c := NewSDWANOverlay(nil).(*sdwanOverlayCollector)
	c.walk = m.walk
	c.publish = pub.publish
	return c
}

func countWalks(m *fakeMIB, prefix []int) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, p := 0, oidStr(prefix)+"."
	for _, w := range m.walks {
		if strings.HasPrefix(w+".", p) {
			n++
		}
	}
	return n
}

func TestCollectorPublishesACapableEdgeAndSkipsTheBFDWalkWhenNothingChanged(t *testing.T) {
	m := newFakeMIB()
	fam := sdwanMIBs[0]
	seedEdge(m, fam, [4]byte{10, 255, 0, 1}, "vedge")
	addSession(m, fam, [4]int{198, 51, 100, 1}, [4]int{198, 51, 100, 2}, [4]byte{10, 255, 0, 2}, 200, 4, 4, 3)
	pub := &publishLog{}
	c := newTestCollector(m, pub)
	tg := Target{ID: "vedge-1", Address: "192.0.2.10"}

	r := c.pollDevice(context.Background(), tg)
	if r.facts == nil || r.err != "" || len(pub.got) != 1 {
		t.Fatalf("first poll: %+v (published %d)", r, len(pub.got))
	}
	f := pub.got[0]
	if f.DeviceID != "vedge-1" || !f.DetailRead || len(f.Peers) != 1 || f.SessionsRead != 1 {
		t.Fatalf("published facts: %+v", f)
	}
	bfdWalks := countWalks(m, fam.bfdEntry)

	// Second poll, nothing changed: identity + TLOC re-read, BFD NOT walked again.
	r = c.pollDevice(context.Background(), tg)
	if r.facts == nil || countWalks(m, fam.bfdEntry) != bfdWalks {
		t.Fatalf("BFD walked again with all sessions up and no flaps (walks %d → %d)", bfdWalks, countWalks(m, fam.bfdEntry))
	}
	if got := pub.got[len(pub.got)-1]; len(got.Peers) != 1 || !got.DetailRead {
		t.Fatalf("carried detail lost: %+v", got)
	}

	// A flap moves the counter → the BFD table is due again.
	m.set(col(fam.tlocEntry, tlocFlap), tlocIdx("GigabitEthernet1", 2), intVal(7))
	c.pollDevice(context.Background(), tg)
	if countWalks(m, fam.bfdEntry) == bfdWalks {
		t.Fatal("a flap did not trigger a BFD re-read")
	}
}

// An unread BFD table is UNKNOWN: the previous detail is kept, never replaced
// by an empty overlay that would read as "no tunnels".
func TestCollectorKeepsPreviousDetailWhenTheBFDWalkFails(t *testing.T) {
	m := newFakeMIB()
	fam := sdwanMIBs[1]
	seedEdge(m, fam, [4]byte{10, 255, 0, 1}, "vedge")
	addSession(m, fam, [4]int{198, 51, 100, 1}, [4]int{198, 51, 100, 2}, [4]byte{10, 255, 0, 2}, 200, 4, 4, 3)
	pub := &publishLog{}
	c := newTestCollector(m, pub)
	tg := Target{ID: "cedge-1", Address: "192.0.2.11"}
	c.pollDevice(context.Background(), tg)

	m.set(col(fam.tlocEntry, tlocUp), tlocIdx("GigabitEthernet1", 2), intVal(2)) // not all up → detail due
	m.failOn[oidStr(col(fam.bfdEntry, bfdSystemIP))] = errors.New("timeout")
	r := c.pollDevice(context.Background(), tg)
	if !strings.HasPrefix(r.err, "bfd walk:") {
		t.Fatalf("err = %q", r.err)
	}
	if got := pub.got[len(pub.got)-1]; len(got.Peers) != 1 || !got.DetailRead {
		t.Fatalf("previous detail was dropped on a failed walk: %+v", got)
	}
}

// A device with no SD-WAN MIB is not published and costs nothing until its
// slow re-probe is due.
func TestCollectorLeavesANonSDWANDeviceAlone(t *testing.T) {
	m := newFakeMIB()
	pub := &publishLog{}
	c := newTestCollector(m, pub)
	tg := Target{ID: "access-sw-1", Address: "192.0.2.12"}
	r := c.pollDevice(context.Background(), tg)
	if !r.probed || r.facts != nil || len(pub.got) != 0 || r.capability != OverlayNotAnswering {
		t.Fatalf("first: %+v published=%d", r, len(pub.got))
	}
	walks := len(m.walks)
	r = c.pollDevice(context.Background(), tg)
	if r.probed || len(m.walks) != walks {
		t.Fatalf("re-probed a non-SD-WAN device before its cadence (walks %d → %d)", walks, len(m.walks))
	}
	// Once the re-probe is due, it is probed again (a later-enabled MIB is noticed).
	c.reprobeOthers = 0
	if r = c.pollDevice(context.Background(), tg); !r.probed {
		t.Fatal("due re-probe did not run")
	}
}

func TestCollectorSurfacesAPublishFailure(t *testing.T) {
	m := newFakeMIB()
	seedEdge(m, sdwanMIBs[0], [4]byte{10, 255, 0, 1}, "vedge")
	pub := &publishLog{fail: errors.New("valkey down")}
	c := newTestCollector(m, pub)
	if r := c.pollDevice(context.Background(), Target{ID: "e", Address: "192.0.2.13"}); !strings.HasPrefix(r.err, "publish:") {
		t.Fatalf("publish failure not surfaced: %+v", r)
	}
}

// ── the real wire: a fake UDP agent serving the MIB through GetNext ─────────

// parseGetNext decodes a v2c GetNext request: request-id and the OID asked for.
func parseGetNext(pkt []byte) (reqID int, oid []int, ok bool) {
	_, msg, _, err := readTLV(pkt)
	if err != nil {
		return 0, nil, false
	}
	_, _, rest, err := readTLV(msg) // version
	if err != nil {
		return 0, nil, false
	}
	_, _, rest, err = readTLV(rest) // community
	if err != nil {
		return 0, nil, false
	}
	tag, pdu, _, err := readTLV(rest)
	if err != nil || tag != 0xA1 {
		return 0, nil, false
	}
	_, rid, p, err := readTLV(pdu)
	if err != nil {
		return 0, nil, false
	}
	_, _, p, _ = readTLV(p) // error-status
	_, _, p, _ = readTLV(p) // error-index
	_, vbl, _, err := readTLV(p)
	if err != nil {
		return 0, nil, false
	}
	_, vb, _, err := readTLV(vbl)
	if err != nil {
		return 0, nil, false
	}
	_, o, _, err := readTLV(vb)
	if err != nil {
		return 0, nil, false
	}
	return int(decodeInt(rid)), decodeOID(o), true
}

func oidLess(a, b []int) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// serveMIB answers GetNext from m over UDP.
func serveMIB(t *testing.T, m *fakeMIB) string {
	t.Helper()
	type row struct {
		oid []int
		v   berVal
	}
	var all []row
	for c, rows := range m.cols {
		ca, _ := parseArcs(c)
		for idx, v := range rows {
			ia, _ := parseArcs(idx)
			all = append(all, row{append(append([]int{}, ca...), ia...), v})
		}
	}
	sort.Slice(all, func(i, j int) bool { return oidLess(all[i].oid, all[j].oid) })
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			rid, asked, ok := parseGetNext(buf[:n])
			if !ok {
				continue
			}
			i := sort.Search(len(all), func(i int) bool { return oidLess(asked, all[i].oid) })
			var resp []byte
			if i >= len(all) {
				resp = snmpResponse(asked, tagEndOfMibView, nil, rid)
			} else {
				resp = snmpResponse(all[i].oid, all[i].v.tag, all[i].v.raw, rid)
			}
			if _, err := conn.WriteTo(resp, peer); err != nil {
				return
			}
		}
	}()
	return conn.LocalAddr().String()
}

// The whole path over real UDP GetNext walks: both families answered from one
// agent's table, the right one is chosen, sessions are folded.
func TestOverlayOverTheWire(t *testing.T) {
	m := newFakeMIB()
	fam := sdwanMIBs[1] // cEdge layout
	seedEdge(m, fam, [4]byte{10, 255, 0, 81}, "vedge")
	addSession(m, fam, [4]int{198, 51, 100, 81}, [4]int{198, 51, 100, 40}, [4]byte{10, 255, 0, 40}, 40, 4, 4, 3)
	addSession(m, fam, [4]int{198, 51, 100, 81}, [4]int{198, 51, 100, 60}, [4]byte{10, 255, 0, 60}, 60, 4, 4, 1)
	addr := serveMIB(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f, err := probeOverlay(ctx, snmpWalkColumnBounded, addr, v2c("public"), lim)
	if err != nil || f.MIB != "cisco-sdwan" || f.SystemIP != "10.255.0.81" || f.Capability != OverlayAvailable {
		t.Fatalf("probe over the wire: %+v err=%v", f, err)
	}
	peers, _, rows, trunc, err := readSessions(ctx, snmpWalkColumnBounded, addr, v2c("public"), f.MIB, lim)
	if err != nil || trunc || rows != 2 || len(peers) != 2 || !peerUp(peers[0]) || peerUp(peers[1]) {
		t.Fatalf("sessions over the wire: peers=%+v rows=%d trunc=%v err=%v", peers, rows, trunc, err)
	}
}

// ── the positional array reader ─────────────────────────────────────────────

func TestRedisArrayKeepsNilPositions(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		r := bufio.NewReader(server)
		_, _ = r.ReadString('\n') // the request; contents irrelevant here
		_, _ = server.Write([]byte("*3\r\n$3\r\nabc\r\n$-1\r\n$2\r\nxy\r\n"))
	}()
	got, err := redisArray(client, 10, "MGET", "a", "b", "c")
	if err != nil || len(got) != 3 || got[0] == nil || *got[0] != "abc" || got[1] != nil || *got[2] != "xy" {
		t.Fatalf("got %v err=%v", got, err)
	}
}

func TestRedisArrayRefusesAnOversizedReply(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		r := bufio.NewReader(server)
		_, _ = r.ReadString('\n')
		_, _ = server.Write([]byte("*500\r\n"))
	}()
	if _, err := redisArray(client, 10, "SMEMBERS", "k"); err == nil {
		t.Fatal("an array past the bound was accepted")
	}
}

// A whole cycle over a mixed estate through the worker pool: every target is
// probed once, only the SD-WAN edge is published, the status counts match.
func TestCollectorCycleOverAMixedEstate(t *testing.T) {
	m := newFakeMIB()
	seedEdge(m, sdwanMIBs[0], [4]byte{10, 255, 0, 1}, "vedge")
	pub := &publishLog{}
	c := newTestCollector(m, pub)
	c.workers = 3
	// The fake MIB answers the same tables for every address, so make the
	// non-SD-WAN devices fail by address: only "edge" reaches the seeded table.
	edgeOnly := func(ctx context.Context, addr string, creds snmpCreds, colOID []int, maxRows int) (map[string]berVal, bool, error) {
		if !strings.HasPrefix(addr, "192.0.2.1:") {
			return nil, false, nil // answers, but with nothing under the SD-WAN subtrees
		}
		return m.walk(ctx, addr, creds, colOID, maxRows)
	}
	c.walk = edgeOnly
	c.targets = func() []Target {
		return []Target{{ID: "edge", Address: "192.0.2.1"}, {ID: "sw1", Address: "192.0.2.2"}, {ID: "sw2", Address: "192.0.2.3"}}
	}
	c.pollOnce(context.Background())
	st := c.Status()
	if st.Targets != 3 || st.Reachable != 3 || !st.Healthy {
		t.Fatalf("status: %+v", st)
	}
	if len(pub.got) != 1 || pub.got[0].DeviceID != "edge" {
		t.Fatalf("published %d: %+v", len(pub.got), pub.got)
	}
}
