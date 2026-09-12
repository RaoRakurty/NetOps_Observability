// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

import (
	"context"
	"strconv"
	"testing"
	"time"
)

// ticketing_pagination_test.go — F-66 (two ticket endpoints had no LIMIT in the
// SQL at all: 22 MB and 3.2 MB responses over append-only tables) and F-67 (the
// links read took a hardcoded 1000 and dropped everything past it silently).
//
// F-67 is the one that corrupts operator behaviour rather than just wasting
// bytes: a link the caller never received renders as {"state":"not_created"},
// so crossing the cliff flips the OLDEST RCAs' badge from a real ServiceNow
// ticket to "no ticket filed" and operators file duplicates against incidents
// that already have them. Measured live at audit time: 973 links, 27 from the
// cliff. These tests push a store past the boundary on purpose.

func seedLinks(t *testing.T, st Store, tenant string, n int) {
	t.Helper()
	base := time.Now().UTC().Add(-time.Duration(n) * time.Minute)
	for i := 0; i < n; i++ {
		l := Link{
			TenantID:       tenant,
			CorrObjectID:   "corr-" + strconv.Itoa(i),
			ExternalSystem: "servicenow",
			TicketNumber:   "INC" + strconv.Itoa(i),
			Status:         "open",
			UpdatedAt:      base.Add(time.Duration(i) * time.Minute),
		}
		if err := st.PutLink(context.Background(), l); err != nil {
			t.Fatalf("seed link %d: %v", i, err)
		}
	}
}

// TestLinksPageReportsTheTrueTotal: the page may be bounded, but the caller must
// be able to tell a partial set from a complete one. Without the total, a client
// joining by correlation id cannot distinguish "no ticket for this object" from
// "this object was past the cliff" — and those render identically today.
func TestLinksPageReportsTheTrueTotal(t *testing.T) {
	st := NewMemStore()
	const seeded = 120
	seedLinks(t, st, "t_a", seeded)

	page, total, err := st.ListLinksForTenant(context.Background(), "t_a", false, 25, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 25 {
		t.Fatalf("page = %d rows, want 25", len(page))
	}
	if total != seeded {
		t.Fatalf("total = %d, want the TRUE row count %d. A page that does not report the "+
			"real total lets a client read a truncated set as the whole set (F-67).", total, seeded)
	}

	// Paging to the end must reach every row exactly once — no cliff, no repeats.
	seen := map[string]bool{}
	for off := 0; off < total; off += 25 {
		rows, _, err := st.ListLinksForTenant(context.Background(), "t_a", false, 25, off)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if seen[r.CorrObjectID] {
				t.Fatalf("offset %d returned %s twice — paging is not stable", off, r.CorrObjectID)
			}
			seen[r.CorrObjectID] = true
		}
	}
	if len(seen) != seeded {
		t.Fatalf("paging reached %d of %d links — rows are unreachable through the API", len(seen), seeded)
	}

	// Past the end is an EMPTY page, never a clamped last page.
	if rows, _, _ := st.ListLinksForTenant(context.Background(), "t_a", false, 25, total+50); len(rows) != 0 {
		t.Fatalf("offset past the end returned %d rows, want 0", len(rows))
	}
}

// TestLinksForCorrHasNoCliff is the actual F-67 fix: a detail surface asks for
// the links of the object it is rendering. The object seeded FIRST is the oldest
// by updated_at, so it sorts last and is exactly the row a truncated top-N page
// drops — the one that would have read as "not_created".
func TestLinksForCorrHasNoCliff(t *testing.T) {
	st := NewMemStore()
	seedLinks(t, st, "t_a", 120)

	oldest := "corr-0"
	page, _, err := st.ListLinksForTenant(context.Background(), "t_a", false, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range page {
		if l.CorrObjectID == oldest {
			t.Fatal("test is not exercising the cliff: the oldest link is inside the first page")
		}
	}

	// ...but the exact lookup still finds it.
	links, err := st.ListLinksForCorr(context.Background(), "t_a", false, oldest)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].TicketNumber != "INC0" {
		t.Fatalf("exact lookup for %s returned %d links (%+v) — a real filed ticket is "+
			"invisible to the detail view, which renders it as 'no ticket filed' and gets a "+
			"duplicate filed against an incident that already has one.", oldest, len(links), links)
	}
}

// TestLinksForCorrIsTenantScoped: the new exact-lookup path is a new read
// surface, so it carries the same 3a obligation as every other one.
func TestLinksForCorrIsTenantScoped(t *testing.T) {
	st := NewMemStore()
	seedLinks(t, st, "t_a", 3)
	seedLinks(t, st, "t_b", 3)

	links, err := st.ListLinksForCorr(context.Background(), "t_b", false, "corr-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range links {
		if l.TenantID != "t_b" {
			t.Fatalf("tenant t_b received a link owned by %q — cross-tenant leak", l.TenantID)
		}
	}
	if len(links) != 1 {
		t.Fatalf("t_b sees %d links for corr-1, want exactly its own 1", len(links))
	}
}

// TestOutboxAndAuditAreBounded guards F-66 directly: neither read may return an
// unbounded table, and both must report the true total.
func TestOutboxAndAuditAreBounded(t *testing.T) {
	st := NewMemStore()
	ctx := context.Background()
	const seeded = 60
	for i := 0; i < seeded; i++ {
		if _, err := st.EnqueueOutbox(ctx, OutboxItem{
			TenantID: "t_a", ID: "o-" + strconv.Itoa(i), CorrObjectID: "c-" + strconv.Itoa(i),
			ExternalSystem: "servicenow", Action: "create", IdempotencyKey: "k-" + strconv.Itoa(i),
			CreatedAt: time.Now().UTC().Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
		if err := st.AppendAudit(ctx, AuditEntry{
			TenantID: "t_a", ID: "a-" + strconv.Itoa(i), CorrObjectID: "c-1",
			ExternalSystem: "servicenow", Action: "create", Result: "ok",
			At: time.Now().UTC().Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatal(err)
		}
	}

	items, total, err := st.ListOutbox(ctx, "t_a", false, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 10 || total != seeded {
		t.Fatalf("outbox page = %d rows / total %d, want 10 / %d", len(items), total, seeded)
	}

	entries, aTotal, err := st.ListAudit(ctx, "t_a", false, "c-1", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 10 || aTotal != seeded {
		t.Fatalf("audit page = %d rows / total %d, want 10 / %d", len(entries), aTotal, seeded)
	}

	// A caller asking for "everything" is still bounded by the storage layer —
	// no internal caller can accidentally pull the whole append-only table.
	if _, _, err := st.ListOutbox(ctx, "t_a", false, 1<<30, 0); err != nil {
		t.Fatal(err)
	}
	if got, _ := boundPageFor(1 << 30); got != MaxPage {
		t.Fatalf("storage-layer clamp = %d, want the %d ceiling", got, MaxPage)
	}
}

// boundPageFor exposes the clamp for assertion.
func boundPageFor(limit int) (int, int) { return boundPage(limit, 0, LinksDefaultPage) }
