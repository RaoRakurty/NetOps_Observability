// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bmp

// store_test.go — the tenant-keyed, bounded record store.
//
// The two properties this file exists to hold:
//   * NO read path returns another tenant's rows, and a principal with no
//     tenant and no cross grant reads NOTHING (default-closed);
//   * memory is bounded in every direction, and every eviction is COUNTED.

import (
	"testing"
)

// newStore builds a store with small bounds so the limits are reachable.
func newStore(t *testing.T, records, ring int) *Store {
	t.Helper()
	return NewStore(fixedClock(), records, ring)
}

// feed opens a session and applies a set of frames to it.
func feed(t *testing.T, s *Store, id, tenant, device string, frames ...[]byte) {
	t.Helper()
	if err := s.Open(id, tenant, device, "192.0.2.1:45000"); err != nil {
		t.Fatalf("Open(%s): %v", id, err)
	}
	for _, f := range frames {
		s.Apply(id, mustParse(t, f))
	}
}

// announce builds a Route Monitoring frame announcing one prefix.
func announce(peer string, as uint32, cidr string) []byte {
	body := updateBody(nil, attrs(
		attr(0x40, attrOrigin, []byte{0}),
		attr(0x40, attrASPath, asPathSeq(true, as, 65999)),
		attr(0x40, attrNextHop, []byte{192, 0, 2, 1}),
	), nlri(cidr))
	return routeMonitoring(0, peer, as, body)
}

// withdraw builds a Route Monitoring frame withdrawing one prefix.
func withdraw(peer string, as uint32, cidr string) []byte {
	return routeMonitoring(0, peer, as, updateBody(nlri(cidr), nil, nil))
}

func TestStoreRefusesASessionWithNoTenant(t *testing.T) {
	s := newStore(t, 8, 8)
	if err := s.Open("bmp-1", "", "dev", "1.2.3.4:1"); err == nil {
		t.Fatal("a session with no tenant must be REFUSED — never stored as tenant \"\"")
	}
	if err := s.Open("bmp-1", "   ", "dev", "1.2.3.4:1"); err == nil {
		t.Fatal("a whitespace tenant is no tenant")
	}
	if got := s.Sessions("", true); len(got) != 0 {
		t.Fatalf("a refused session was stored anyway: %v", got)
	}
}

func TestStoreSessionsAreOwnTenantOnly(t *testing.T) {
	s := newStore(t, 16, 16)
	feed(t, s, "bmp-1", "acme", "acme-core", initiation("acme-rtr", "d"), announce("192.0.2.10", 64512, "10.1.0.0/24"))
	feed(t, s, "bmp-2", "globex", "gx-edge", initiation("gx-rtr", "d"), announce("198.51.100.7", 65001, "203.0.113.0/24"))

	acme := s.Sessions("acme", false)
	if len(acme) != 1 || acme[0].DeviceID != "acme-core" {
		t.Fatalf("acme sees %+v", acme)
	}
	if acme[0].Router != "acme-rtr" {
		t.Fatalf("router name = %q", acme[0].Router)
	}
	globex := s.Sessions("globex", false)
	if len(globex) != 1 || globex[0].DeviceID != "gx-edge" {
		t.Fatalf("globex sees %+v", globex)
	}
	// Default-closed: no tenant and no cross grant reads NOTHING.
	if got := s.Sessions("", false); len(got) != 0 {
		t.Fatalf("a tenant-less scoped principal read %d sessions — must be 0", len(got))
	}
	// Only a cross-tenant principal sees both.
	if got := s.Sessions("", true); len(got) != 2 {
		t.Fatalf("cross-tenant sees %d sessions, want 2", len(got))
	}
}

func TestStoreUpdatesAreOwnTenantOnly(t *testing.T) {
	s := newStore(t, 16, 16)
	feed(t, s, "bmp-1", "acme", "acme-core", announce("192.0.2.10", 64512, "10.1.0.0/24"))
	feed(t, s, "bmp-2", "globex", "gx-edge", announce("198.51.100.7", 65001, "203.0.113.0/24"))

	acme := s.Updates("acme", false, UpdateFilter{Limit: 50})
	if len(acme) != 1 || acme[0].Prefix != "10.1.0.0/24" {
		t.Fatalf("acme updates = %+v", acme)
	}
	for _, u := range acme {
		if u.DeviceID == "gx-edge" || u.Prefix == "203.0.113.0/24" {
			t.Fatalf("CROSS-TENANT LEAK: %+v", u)
		}
	}
	if got := s.Updates("", false, UpdateFilter{Limit: 50}); len(got) != 0 {
		t.Fatalf("a tenant-less scoped principal read %d updates — must be 0", len(got))
	}
	if got := s.Updates("", true, UpdateFilter{Limit: 50}); len(got) != 2 {
		t.Fatalf("cross-tenant sees %d updates, want 2", len(got))
	}
}

func TestStoreStatsAreOwnTenantOnly(t *testing.T) {
	s := newStore(t, 16, 16)
	feed(t, s, "bmp-1", "acme", "acme-core", peerUp(0, "192.0.2.10", 64512), announce("192.0.2.10", 64512, "10.1.0.0/24"))
	feed(t, s, "bmp-2", "globex", "gx-edge",
		peerUp(0, "198.51.100.7", 65001),
		announce("198.51.100.7", 65001, "203.0.113.0/24"),
		announce("198.51.100.7", 65001, "203.0.114.0/24"))

	acme := s.Stats("acme", false)
	if acme.Sessions != 1 || acme.UpdatesHeld != 1 || acme.Peers != 1 || acme.PeersUp != 1 {
		t.Fatalf("acme stats = %+v", acme)
	}
	globex := s.Stats("globex", false)
	if globex.UpdatesHeld != 2 {
		t.Fatalf("globex stats = %+v", globex)
	}
	if none := s.Stats("", false); none.Sessions != 0 || none.UpdatesHeld != 0 {
		t.Fatalf("tenant-less stats = %+v, want all zero", none)
	}
	if all := s.Stats("", true); all.Sessions != 2 || all.UpdatesHeld != 3 {
		t.Fatalf("cross-tenant stats = %+v", all)
	}
}

func TestRingDropsOldestAndCountsIt(t *testing.T) {
	s := newStore(t, 4, 3) // ring depth 3
	if err := s.Open("bmp-1", "acme", "dev", "1.2.3.4:1"); err != nil {
		t.Fatal(err)
	}
	total := 0
	for i := 0; i < 10; i++ {
		cidr := []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24", "10.0.4.0/24",
			"10.0.5.0/24", "10.0.6.0/24", "10.0.7.0/24", "10.0.8.0/24", "10.0.9.0/24"}[i]
		a := s.Apply("bmp-1", mustParse(t, announce("192.0.2.10", 64512, cidr)))
		total += a.DroppedUpdates
	}
	if total != 7 {
		t.Fatalf("dropped = %d, want 7 (10 pushed into a ring of 3)", total)
	}
	held := s.Updates("acme", false, UpdateFilter{Limit: 50})
	if len(held) != 3 {
		t.Fatalf("held = %d, want the ring depth 3", len(held))
	}
	// Newest first, and the OLDEST were the ones dropped.
	if held[0].Prefix != "10.0.9.0/24" || held[2].Prefix != "10.0.7.0/24" {
		t.Fatalf("ring contents = %v %v %v", held[0].Prefix, held[1].Prefix, held[2].Prefix)
	}
	st := s.Stats("acme", false)
	if st.UpdatesDropped != 7 {
		t.Fatalf("stats dropped = %d, want 7 — backpressure must be VISIBLE", st.UpdatesDropped)
	}
	view := s.Sessions("acme", false)[0]
	if view.Dropped != 7 || view.Updates != 3 {
		t.Fatalf("session view = %+v", view)
	}
}

func TestSessionRecordsAreCappedAndEvictClosedOnesFirst(t *testing.T) {
	s := newStore(t, 2, 4)
	if err := s.Open("bmp-1", "acme", "d1", "1.1.1.1:1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Open("bmp-2", "acme", "d2", "1.1.1.2:1"); err != nil {
		t.Fatal(err)
	}
	// Both live: a third must be REFUSED rather than evicting a live session.
	if err := s.Open("bmp-3", "acme", "d3", "1.1.1.3:1"); err == nil {
		t.Fatal("a third session must be refused while both records are LIVE")
	}
	s.Close("bmp-1", "peer closed")
	if err := s.Open("bmp-3", "acme", "d3", "1.1.1.3:1"); err != nil {
		t.Fatalf("after a close, a new session must fit: %v", err)
	}
	ids := map[string]bool{}
	for _, v := range s.Sessions("acme", false) {
		ids[v.ID] = true
	}
	if ids["bmp-1"] || !ids["bmp-2"] || !ids["bmp-3"] {
		t.Fatalf("evicted the wrong record: %v", ids)
	}
}

func TestDuplicateSessionIDIsRefused(t *testing.T) {
	s := newStore(t, 8, 4)
	if err := s.Open("bmp-1", "acme", "d1", "1.1.1.1:1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Open("bmp-1", "globex", "d2", "1.1.1.2:1"); err == nil {
		t.Fatal("a duplicate session id must be refused — two routers' feeds must never merge")
	}
	if v := s.Sessions("globex", false); len(v) != 0 {
		t.Fatalf("the refused session leaked into globex: %+v", v)
	}
}

func TestClosingASessionMakesPeerStateUnknownNotStaleUp(t *testing.T) {
	s := newStore(t, 8, 8)
	feed(t, s, "bmp-1", "acme", "d1", peerUp(0, "192.0.2.10", 64512))
	if v := s.Sessions("acme", false)[0]; v.Peers[0].State != "up" {
		t.Fatalf("peer state = %q, want up", v.Peers[0].State)
	}
	s.Close("bmp-1", "peer closed")
	v := s.Sessions("acme", false)[0]
	if v.State != "closed" || v.CloseReason != "peer closed" {
		t.Fatalf("session = %+v", v)
	}
	if v.Peers[0].State != "unknown" {
		t.Fatalf("after the feed died the peer state is %q — a stale \"up\" is the lie this module must not tell", v.Peers[0].State)
	}
}

func TestPeerStateIsUnknownUntilObserved(t *testing.T) {
	// A Route Monitoring message creates the peer record, but no Peer Up has
	// been seen — so the state is unknown, not assumed up.
	s := newStore(t, 8, 8)
	feed(t, s, "bmp-1", "acme", "d1", announce("192.0.2.10", 64512, "10.0.0.0/8"))
	v := s.Sessions("acme", false)[0]
	if len(v.Peers) != 1 || v.Peers[0].State != "unknown" {
		t.Fatalf("peers = %+v", v.Peers)
	}
	if v.Peers[0].Announces != 1 {
		t.Fatalf("announce not counted against the peer: %+v", v.Peers[0])
	}
}

func TestPeerDownRecordsTheReason(t *testing.T) {
	s := newStore(t, 8, 8)
	feed(t, s, "bmp-1", "acme", "d1",
		peerUp(0, "192.0.2.10", 64512),
		peerDownNotification("192.0.2.10", 64512, 6, 2))
	v := s.Sessions("acme", false)[0]
	if v.Peers[0].State != "down" || v.Peers[0].DownReason != "local_notification" {
		t.Fatalf("peer = %+v", v.Peers[0])
	}
}

func TestWithdrawCarriesNoPathAttributes(t *testing.T) {
	s := newStore(t, 8, 8)
	feed(t, s, "bmp-1", "acme", "d1", withdraw("192.0.2.10", 64512, "10.5.0.0/16"))
	rows := s.Updates("acme", false, UpdateFilter{Limit: 10})
	if len(rows) != 1 || rows[0].Kind != "withdraw" {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].NextHop != "" || len(rows[0].ASPath) != 0 || rows[0].Origin != "" {
		t.Fatalf("a withdrawal must carry no path attributes: %+v", rows[0])
	}
}

func TestUpdateFiltersNarrowWithoutWideningScope(t *testing.T) {
	s := newStore(t, 8, 64)
	feed(t, s, "bmp-1", "acme", "d1",
		announce("192.0.2.10", 64512, "10.1.2.0/24"),
		announce("192.0.2.10", 64512, "10.9.0.0/16"),
		announce("198.51.100.9", 64512, "172.16.0.0/12"))
	feed(t, s, "bmp-2", "globex", "d2", announce("192.0.2.10", 64512, "10.1.2.0/24"))

	// A supernet filter finds the more-specific prefixes inside it.
	byPrefix := s.Updates("acme", false, UpdateFilter{Limit: 10, HasPrefix: true, Prefix: mustPrefix("10.0.0.0/8")})
	if len(byPrefix) != 2 {
		t.Fatalf("prefix filter = %+v", byPrefix)
	}
	// And it does NOT reach into another tenant's identical prefix.
	for _, u := range byPrefix {
		if u.SessionID == "bmp-2" {
			t.Fatalf("filter crossed the tenant boundary: %+v", u)
		}
	}
	// A more-specific filter than the record does not match it.
	if got := s.Updates("acme", false, UpdateFilter{Limit: 10, HasPrefix: true, Prefix: mustPrefix("10.1.2.128/25")}); len(got) != 0 {
		t.Fatalf("a /25 filter matched a /24 record: %+v", got)
	}
	byPeer := s.Updates("acme", false, UpdateFilter{Limit: 10, Peer: "198.51.100.9"})
	if len(byPeer) != 1 || byPeer[0].Prefix != "172.16.0.0/12" {
		t.Fatalf("peer filter = %+v", byPeer)
	}
	bySession := s.Updates("acme", false, UpdateFilter{Limit: 10, Session: "bmp-2"})
	if len(bySession) != 0 {
		t.Fatalf("session filter must NARROW, never widen: %+v", bySession)
	}
	// An IPv6 filter must not match IPv4 records.
	if got := s.Updates("acme", false, UpdateFilter{Limit: 10, HasPrefix: true, Prefix: mustPrefix("::/0")}); len(got) != 0 {
		t.Fatalf("a v6 filter matched v4 records: %+v", got)
	}
}

func TestUpdatesAreNewestFirstAndPageByCursor(t *testing.T) {
	s := newStore(t, 8, 64)
	if err := s.Open("bmp-1", "acme", "d1", "1.1.1.1:1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		s.Apply("bmp-1", mustParse(t, announce("192.0.2.10", 64512, cidrN(i))))
	}
	page1 := s.Updates("acme", false, UpdateFilter{Limit: 4})
	if len(page1) != 4 || page1[0].Prefix != cidrN(9) {
		t.Fatalf("page 1 = %+v", page1)
	}
	for i := 1; i < len(page1); i++ {
		if page1[i-1].Seq <= page1[i].Seq {
			t.Fatalf("page is not newest-first: %d then %d", page1[i-1].Seq, page1[i].Seq)
		}
	}
	page2 := s.Updates("acme", false, UpdateFilter{Limit: 4, Before: page1[3].Seq})
	if len(page2) != 4 || page2[0].Prefix != cidrN(5) {
		t.Fatalf("page 2 = %+v", page2)
	}
	// Pages must not overlap.
	seen := map[uint64]bool{}
	for _, u := range append(append([]UpdateView{}, page1...), page2...) {
		if seen[u.Seq] {
			t.Fatalf("seq %d appeared in two pages", u.Seq)
		}
		seen[u.Seq] = true
	}
	page3 := s.Updates("acme", false, UpdateFilter{Limit: 4, Before: page2[3].Seq})
	if len(page3) != 2 {
		t.Fatalf("final page = %d rows, want the 2 remaining", len(page3))
	}
	if last := s.Updates("acme", false, UpdateFilter{Limit: 4, Before: page3[1].Seq}); len(last) != 0 {
		t.Fatalf("walking past the end returned %d rows", len(last))
	}
}

func TestUpdatesMergeSessionsInSequenceOrder(t *testing.T) {
	s := newStore(t, 8, 64)
	if err := s.Open("bmp-1", "acme", "d1", "1.1.1.1:1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Open("bmp-2", "acme", "d2", "1.1.1.2:1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		id := "bmp-1"
		if i%2 == 1 {
			id = "bmp-2"
		}
		s.Apply(id, mustParse(t, announce("192.0.2.10", 64512, cidrN(i))))
	}
	rows := s.Updates("acme", false, UpdateFilter{Limit: 6})
	if len(rows) != 6 {
		t.Fatalf("rows = %d", len(rows))
	}
	for i := 1; i < len(rows); i++ {
		if rows[i-1].Seq <= rows[i].Seq {
			t.Fatalf("merge is not globally newest-first: %+v", rows)
		}
	}
	if rows[0].SessionID != "bmp-2" || rows[1].SessionID != "bmp-1" {
		t.Fatalf("interleave lost: %s then %s", rows[0].SessionID, rows[1].SessionID)
	}
}

func TestUpdatesLimitIsHonouredExactly(t *testing.T) {
	s := newStore(t, 8, 64)
	if err := s.Open("bmp-1", "acme", "d1", "1.1.1.1:1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		s.Apply("bmp-1", mustParse(t, announce("192.0.2.10", 64512, cidrN(i))))
	}
	for _, n := range []int{1, 3, 7, 20} {
		if got := s.Updates("acme", false, UpdateFilter{Limit: n}); len(got) != n {
			t.Fatalf("limit %d returned %d rows", n, len(got))
		}
	}
	// A zero limit must not mean "everything".
	if got := s.Updates("acme", false, UpdateFilter{}); len(got) > 1 {
		t.Fatalf("a zero limit returned %d rows — it must never mean unbounded", len(got))
	}
}

func TestApplyToAnUnknownSessionIsANoOp(t *testing.T) {
	s := newStore(t, 4, 4)
	if got := s.Apply("nope", mustParse(t, announce("192.0.2.10", 64512, "10.0.0.0/8"))); got.StoredUpdates != 0 {
		t.Fatalf("applied to a session that does not exist: %+v", got)
	}
	s.RecordParseError("nope") // must not panic
	s.Close("nope", "x")       // must not panic
	if got := s.Apply("nope", nil); got.StoredUpdates != 0 {
		t.Fatalf("a nil message must be a no-op: %+v", got)
	}
}

func TestParseErrorsAreCountedAgainstTheSession(t *testing.T) {
	s := newStore(t, 4, 4)
	if err := s.Open("bmp-1", "acme", "d1", "1.1.1.1:1"); err != nil {
		t.Fatal(err)
	}
	s.RecordParseError("bmp-1")
	s.RecordParseError("bmp-1")
	if v := s.Sessions("acme", false)[0]; v.ParseErrors != 2 {
		t.Fatalf("parse errors = %d, want 2", v.ParseErrors)
	}
	if st := s.Stats("acme", false); st.ParseErrors != 2 {
		t.Fatalf("stats parse errors = %d", st.ParseErrors)
	}
}

func TestUnsupportedElementsAreCountedAgainstTheSession(t *testing.T) {
	s := newStore(t, 4, 8)
	val := append([]byte{}, be16(afiIPv4)...)
	val = append(val, 128, 0, 0)
	body := updateBody(nil, attrs(
		attrExt(0x80, attrMPReachNLRI, val),
		attr(0xC0, 200, []byte{1}),
	), nil)
	feed(t, s, "bmp-1", "acme", "d1", routeMonitoring(0, "192.0.2.10", 64512, body))
	if st := s.Stats("acme", false); st.Unsupported != 2 {
		t.Fatalf("unsupported = %d, want 2 (one family + one attribute)", st.Unsupported)
	}
}

func TestSessionRIBIsRecordedPerPeer(t *testing.T) {
	s := newStore(t, 4, 8)
	feed(t, s, "bmp-1", "acme", "d1",
		peerUp(peerFlagL, "192.0.2.10", 64512),
		peerUp(peerFlagO, "192.0.2.11", 64512))
	v := s.Sessions("acme", false)[0]
	got := map[string]string{}
	for _, p := range v.Peers {
		got[p.Address] = p.RIB
	}
	if got["192.0.2.10"] != ribInPost || got["192.0.2.11"] != ribOut {
		t.Fatalf("rib per peer = %+v — an Adj-RIB-Out must never be presented as an Adj-RIB-In", got)
	}
}

func TestMessageCountsPerSession(t *testing.T) {
	s := newStore(t, 4, 8)
	feed(t, s, "bmp-1", "acme", "d1",
		initiation("r", "d"),
		peerUp(0, "192.0.2.10", 64512),
		announce("192.0.2.10", 64512, "10.0.0.0/8"),
		announce("192.0.2.10", 64512, "10.1.0.0/16"),
		statsReport("192.0.2.10", map[uint16]uint32{0: 1}))
	v := s.Sessions("acme", false)[0]
	if v.Messages["route_monitoring"] != 2 || v.Messages["initiation"] != 1 || v.Messages["statistics_report"] != 1 {
		t.Fatalf("messages = %+v", v.Messages)
	}
	if st := s.Stats("acme", false); st.Messages["route_monitoring"] != 2 {
		t.Fatalf("stats messages = %+v", st.Messages)
	}
}

func TestPeerTableIsCappedAndSaysSo(t *testing.T) {
	s := newStore(t, 2, 4)
	if err := s.Open("bmp-1", "acme", "d1", "1.1.1.1:1"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxPeersPerSession+5; i++ {
		addr := peerAddrN(i)
		s.Apply("bmp-1", mustParse(t, peerUp(0, addr, 64512)))
	}
	v := s.Sessions("acme", false)[0]
	if len(v.Peers) != maxPeersPerSession {
		t.Fatalf("peers = %d, want the cap %d", len(v.Peers), maxPeersPerSession)
	}
	if !v.PeersPartial {
		t.Fatal("the peer table hit its cap without saying so — a truncated table must never read as complete")
	}
}

func TestTerminationMarksTheReasonWithoutClosing(t *testing.T) {
	s := newStore(t, 4, 4)
	feed(t, s, "bmp-1", "acme", "d1", termination(0))
	v := s.Sessions("acme", false)[0]
	if v.CloseReason != "router sent termination" {
		t.Fatalf("close note = %q", v.CloseReason)
	}
}

func TestRingHelpersAreBoundedAtTheEdges(t *testing.T) {
	r := newUpdateRing(0) // a zero capacity must not mean unbounded
	if len(r.buf) != 1 {
		t.Fatalf("ring capacity = %d, want the safe floor of 1", len(r.buf))
	}
	r.push(UpdateRecord{Seq: 1})
	r.push(UpdateRecord{Seq: 2})
	if r.dropped != 1 || r.count != 1 {
		t.Fatalf("ring = count %d dropped %d", r.count, r.dropped)
	}
	var seen []uint64
	r.newestFirst(func(rec UpdateRecord) bool { seen = append(seen, rec.Seq); return true })
	if len(seen) != 1 || seen[0] != 2 {
		t.Fatalf("newestFirst = %v", seen)
	}
	// The walk stops when the callback says so.
	r2 := newUpdateRing(4)
	for i := uint64(1); i <= 4; i++ {
		r2.push(UpdateRecord{Seq: i})
	}
	n := 0
	r2.newestFirst(func(UpdateRecord) bool { n++; return n < 2 })
	if n != 2 {
		t.Fatalf("callback stop ignored: walked %d", n)
	}
}

func TestNewStoreFallsBackToSafeBounds(t *testing.T) {
	s := NewStore(nil, 0, 0)
	if s.maxRecs != MaxSessionRecords || s.ringDepth != MaxUpdatesPerSession {
		t.Fatalf("zero bounds = %d/%d, want the package constants", s.maxRecs, s.ringDepth)
	}
	if s.now == nil {
		t.Fatal("a nil clock must fall back to time.Now")
	}
}
