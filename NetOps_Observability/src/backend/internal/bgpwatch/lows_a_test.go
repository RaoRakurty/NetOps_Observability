// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpwatch

// lows_a_test.go — review findings 3.4-08 and 3.4-09.

import (
	"net/netip"
	"strings"
	"testing"
)

// 3.4-08 — A DEFAULT ROUTE IS NOT AN UNALLOCATED BOGON, IN EITHER FAMILY.
//
// The IPv6 architecture rule tested the network ADDRESS only. `::` is not in
// 2000::/3, so ::/0 — a prefix that COVERS global unicast rather than sitting
// outside it — was reported as an unallocated bogon and raised a high-severity
// incident for anyone watching a v6 default route. 0.0.0.0/0 correctly was not,
// so the two families disagreed about the same question, and the doc comment on
// Lookup says covering a reserved block is not a bogon announcement.
func TestDefaultRoutesAreNotBogonsInEitherFamily(t *testing.T) {
	s := NewBogonSet()
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "::/1", "::/2"} {
		p := netip.MustParsePrefix(cidr)
		if e, ok := s.Lookup(p); ok {
			t.Errorf("%s was reported as a bogon (%s: %s) — it COVERS reserved space, it does not sit inside it",
				cidr, e.Reason, e.Why)
		}
	}
	// The rule itself still holds for prefixes that really are outside 2000::/3.
	for _, cidr := range []string{"4000::/16", "e000::/20"} {
		if _, ok := s.Lookup(netip.MustParsePrefix(cidr)); !ok {
			t.Errorf("%s is outside 2000::/3 and was NOT reported — the architecture rule stopped working", cidr)
		}
	}
	// And a real allocated global-unicast prefix is still clean. (2001:db8::/32
	// would NOT be: documentation space is in the embedded reserved table.)
	if e, ok := s.Lookup(netip.MustParsePrefix("2a00:1450:4001::/48")); ok {
		t.Errorf("allocated global unicast inside 2000::/3 was flagged: %s", e.Reason)
	}
}

// 3.4-09 — A TRUNCATED FEED IS NOT A CLEAN REFRESH.
//
// A fetch that hit the 20,000-entry cap (and every unparsable row) was stored
// as a clean refresh: entries reported, error empty, nothing said about the
// rows that were never compiled — and no retry for the whole 6-hour TTL.
func TestFeedStatusDeclaresTruncationAndDroppedRows(t *testing.T) {
	s := NewBogonSet()
	s.mu.Lock()
	s.feedURL, s.feedCount, s.feedTruncated, s.feedDropped = "https://example.test/bogons.txt", FeedMaxEntries, true, 4
	s.mu.Unlock()

	st := s.FeedStatus(true)
	if !st.Truncated {
		t.Fatal("a refresh that hit the entry cap reported itself as complete")
	}
	if st.Dropped != 4 {
		t.Fatalf("dropped rows = %d, want 4", st.Dropped)
	}
	if !strings.Contains(st.Note, "SHORT") {
		t.Fatalf("the status does not tell the operator the list is short: %q", st.Note)
	}
}

// parseFullBogons already counts what it refuses; this pins that the counts the
// status reports come from it rather than from a guess.
func TestParseFullBogonsCountsWhatItRefuses(t *testing.T) {
	body := "# comment\n10.0.0.0/8\nnot-a-cidr\n\n192.0.2.0/24\n300.1.2.3/24\n"
	rules, kept, dropped := parseFullBogons(body)
	if kept != 2 || len(rules) != 2 {
		t.Fatalf("kept = %d (%d rules), want 2", kept, len(rules))
	}
	if dropped != 2 {
		t.Fatalf("dropped = %d, want 2", dropped)
	}
}
