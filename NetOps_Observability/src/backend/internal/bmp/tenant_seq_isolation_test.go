// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bmp

// tenant_seq_isolation_test.go — the sequence number a tenant is handed must
// not be a side-channel onto the fleet's message volume (§3a).
//
// The store keeps ONE process-wide arrival counter so a cross-tenant read can
// merge several tenants' rings in true arrival order. Publishing that counter
// to a tenant-scoped caller would let tenant A subtract two of its OWN
// consecutive rows and read off exactly how many BMP records every other tenant
// wrote in between — the same fleet-volume fact handleStats deliberately
// withholds ("another tenant's message volume is another tenant's data").
//
// So a scoped caller pages by a DENSE per-tenant counter, and this file holds
// both halves of that: the numbers carry no foreign volume, AND ordering and
// cursor paging still return exactly the right rows in the right order for a
// scoped caller and for a cross-tenant one.

import (
	"fmt"
	"testing"
)

// interleaveTwoTenants opens one session per tenant and feeds them in a
// deliberately lumpy interleaving, so a leaked global counter shows up as
// obvious gaps rather than an off-by-one.
//
// It returns the announced prefixes in arrival order per tenant.
func interleaveTwoTenants(t *testing.T, s *Store) (acme, globex []string) {
	t.Helper()
	if err := s.Open("bmp-1", "acme", "acme-core", "192.0.2.1:45000"); err != nil {
		t.Fatalf("Open acme: %v", err)
	}
	if err := s.Open("bmp-2", "globex", "gx-edge", "198.51.100.1:45000"); err != nil {
		t.Fatalf("Open globex: %v", err)
	}
	// acme writes 1 record for every `burst` records globex writes.
	bursts := []int{3, 1, 7, 2, 5}
	for i, burst := range bursts {
		pfx := fmt.Sprintf("10.1.%d.0/24", i)
		s.Apply("bmp-1", mustParse(t, announce("192.0.2.10", 64512, pfx)))
		acme = append(acme, pfx)
		for j := 0; j < burst; j++ {
			gpfx := fmt.Sprintf("203.0.%d.0/24", len(globex))
			s.Apply("bmp-2", mustParse(t, announce("198.51.100.7", 65001, gpfx)))
			globex = append(globex, gpfx)
		}
	}
	return acme, globex
}

// TestScopedSequenceIsDenseAndLeaksNoForeignVolume is the isolation test: a
// tenant's published sequence numbers must be 1..N with no gaps, whatever any
// other tenant was doing at the time.
func TestScopedSequenceIsDenseAndLeaksNoForeignVolume(t *testing.T) {
	s := newStore(t, 8, 256)
	acmePrefixes, globexPrefixes := interleaveTwoTenants(t, s)

	rows := s.Updates(Principal{Tenant: "acme"}, UpdateFilter{Limit: 100})
	if len(rows) != len(acmePrefixes) {
		t.Fatalf("acme sees %d rows, wrote %d", len(rows), len(acmePrefixes))
	}
	// Newest-first, so the sequences must read N, N-1, … 1 exactly.
	for i, row := range rows {
		want := uint64(len(acmePrefixes) - i)
		if row.Seq != want {
			t.Fatalf("acme row %d published seq %d, want %d — a gap here is a count of ANOTHER tenant's records (rows: %v)",
				i, row.Seq, want, seqsOf(rows))
		}
	}

	// The same assertion stated as the leak it prevents: the span of acme's
	// sequence space must equal acme's own record count. Under the global
	// counter the span would be acme+globex.
	st := s.Stats(Principal{Tenant: "acme"})
	if st.OldestUpdateSeq != 1 || st.NewestUpdateSeq != uint64(len(acmePrefixes)) {
		t.Fatalf("acme stats seq span = [%d,%d], want [1,%d] — the span must count acme's %d records, not the fleet's %d",
			st.OldestUpdateSeq, st.NewestUpdateSeq, len(acmePrefixes),
			len(acmePrefixes), len(acmePrefixes)+len(globexPrefixes))
	}

	// Globex gets its own dense space, starting at 1 too — neither tenant's
	// numbering says anything about when it started relative to the other.
	grows := s.Updates(Principal{Tenant: "globex"}, UpdateFilter{Limit: 100})
	if len(grows) != len(globexPrefixes) {
		t.Fatalf("globex sees %d rows, wrote %d", len(grows), len(globexPrefixes))
	}
	for i, row := range grows {
		if want := uint64(len(globexPrefixes) - i); row.Seq != want {
			t.Fatalf("globex row %d published seq %d, want %d", i, row.Seq, want)
		}
	}
}

// TestScopedSequenceIsDenseAcrossASecondSession holds the property that makes
// the per-tenant counter a valid keyset key: it is monotonic across ALL of one
// tenant's sessions, not restarted per connection.
func TestScopedSequenceIsDenseAcrossASecondSession(t *testing.T) {
	s := newStore(t, 8, 256)
	if err := s.Open("bmp-1", "acme", "acme-core", "192.0.2.1:45000"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Open("bmp-2", "globex", "gx-edge", "198.51.100.1:45000"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.Apply("bmp-1", mustParse(t, announce("192.0.2.10", 64512, "10.1.0.0/24")))
	s.Apply("bmp-2", mustParse(t, announce("198.51.100.7", 65001, "203.0.113.0/24")))

	// acme's SECOND router connects and announces.
	if err := s.Open("bmp-3", "acme", "acme-edge", "192.0.2.9:45000"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.Apply("bmp-3", mustParse(t, announce("192.0.2.11", 64512, "10.2.0.0/24")))
	s.Apply("bmp-1", mustParse(t, announce("192.0.2.10", 64512, "10.1.1.0/24")))

	rows := s.Updates(Principal{Tenant: "acme"}, UpdateFilter{Limit: 100})
	if len(rows) != 3 {
		t.Fatalf("acme sees %d rows, want 3", len(rows))
	}
	// Newest-first across two sessions, numbered 3,2,1 — one continuous space.
	want := []struct {
		seq    uint64
		prefix string
	}{
		{3, "10.1.1.0/24"},
		{2, "10.2.0.0/24"},
		{1, "10.1.0.0/24"},
	}
	for i, w := range want {
		if rows[i].Seq != w.seq || rows[i].Prefix != w.prefix {
			t.Fatalf("row %d = seq %d %s, want seq %d %s (seqs: %v)",
				i, rows[i].Seq, rows[i].Prefix, w.seq, w.prefix, seqsOf(rows))
		}
	}
}

// TestScopedCursorPagingWalksTheTenantFeedExactlyOnce proves the dense key is
// still a correct keyset cursor: every row once, newest-first, no skips.
func TestScopedCursorPagingWalksTheTenantFeedExactlyOnce(t *testing.T) {
	s := newStore(t, 8, 256)
	acmePrefixes, _ := interleaveTwoTenants(t, s)

	seen := map[string]bool{}
	var order []uint64
	var before uint64
	for page := 0; ; page++ {
		if page > 20 {
			t.Fatal("paging did not terminate")
		}
		rows := s.Updates(Principal{Tenant: "acme"}, UpdateFilter{Limit: 2, Before: before})
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			if seen[r.Prefix] {
				t.Fatalf("prefix %s appeared in two pages", r.Prefix)
			}
			seen[r.Prefix] = true
			order = append(order, r.Seq)
		}
		before = rows[len(rows)-1].Seq
	}
	if len(seen) != len(acmePrefixes) {
		t.Fatalf("paging walked %d of acme's %d rows", len(seen), len(acmePrefixes))
	}
	for i := 1; i < len(order); i++ {
		if order[i-1] <= order[i] {
			t.Fatalf("paging is not strictly newest-first: %v", order)
		}
	}
	for _, p := range acmePrefixes {
		if !seen[p] {
			t.Fatalf("paging never returned %s", p)
		}
	}
}

// TestCrossTenantLensStillMergesInTrueArrivalOrder is the other half: swapping
// the scoped key must not cost the platform operator a correct cross-tenant
// merge. The cross principal keeps the process-wide key — the one number that
// orders two tenants' rings against each other.
func TestCrossTenantLensStillMergesInTrueArrivalOrder(t *testing.T) {
	s := newStore(t, 8, 256)
	acmePrefixes, globexPrefixes := interleaveTwoTenants(t, s)
	total := len(acmePrefixes) + len(globexPrefixes)

	cross := Principal{Cross: true}
	rows := s.Updates(cross, UpdateFilter{Limit: 100})
	if len(rows) != total {
		t.Fatalf("cross-tenant read sees %d rows, want %d", len(rows), total)
	}
	// The global counter is dense over the WHOLE fleet, so newest-first reads
	// total, total-1, … 1. That is the arrival order both feeds really had.
	for i, row := range rows {
		if want := uint64(total - i); row.Seq != want {
			t.Fatalf("cross row %d seq %d, want %d (seqs: %v)", i, row.Seq, want, seqsOf(rows))
		}
	}

	// And the cross lens pages correctly through the merged feed.
	seen := map[string]bool{}
	var before uint64
	for page := 0; ; page++ {
		if page > 40 {
			t.Fatal("cross paging did not terminate")
		}
		got := s.Updates(cross, UpdateFilter{Limit: 3, Before: before})
		if len(got) == 0 {
			break
		}
		for _, r := range got {
			if seen[r.Prefix] {
				t.Fatalf("cross paging repeated %s", r.Prefix)
			}
			seen[r.Prefix] = true
		}
		before = got[len(got)-1].Seq
	}
	if len(seen) != total {
		t.Fatalf("cross paging walked %d of %d rows", len(seen), total)
	}

	// The cross principal is entitled to the fleet span; the scoped one is not.
	cst := s.Stats(cross)
	if cst.OldestUpdateSeq != 1 || cst.NewestUpdateSeq != uint64(total) {
		t.Fatalf("cross stats seq span = [%d,%d], want [1,%d]", cst.OldestUpdateSeq, cst.NewestUpdateSeq, total)
	}
}

// TestReplayedForeignCursorPagesOnlyTheCallersOwnRows: a cursor is opaque and
// is NOT a security boundary. One minted by acme and replayed by globex must
// page globex's own rows in globex's own space — never reach acme's.
func TestReplayedForeignCursorPagesOnlyTheCallersOwnRows(t *testing.T) {
	s := newStore(t, 8, 256)
	interleaveTwoTenants(t, s)

	acmeRows := s.Updates(Principal{Tenant: "acme"}, UpdateFilter{Limit: 2})
	if len(acmeRows) != 2 {
		t.Fatalf("acme page = %d rows", len(acmeRows))
	}
	stolen := acmeRows[len(acmeRows)-1].Seq

	got := s.Updates(Principal{Tenant: "globex"}, UpdateFilter{Limit: 50, Before: stolen})
	for _, r := range got {
		if r.DeviceID != "gx-edge" {
			t.Fatalf("globex read acme's row via a replayed cursor: %+v", r)
		}
		if r.Seq >= stolen {
			t.Fatalf("cursor %d was not honoured in globex's own space: got seq %d", stolen, r.Seq)
		}
	}
}

func seqsOf(rows []UpdateView) []uint64 {
	out := make([]uint64, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Seq)
	}
	return out
}
