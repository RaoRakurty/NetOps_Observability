package bgpwatch

// watchlist_test.go — the WatchFileStore's own unit suite (§11). The
// cross-BACKEND contract table and the HTTP cross-org isolation proof live in
// the root package (bgp_watchlist_isolation_test.go), where the Postgres twin
// and the handler are.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func newTestWatchStore(t *testing.T) (*WatchFileStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bgp_watchlist.json")
	return NewWatchFileStore(path), path
}

func mustAdd(t *testing.T, s *WatchFileStore, tenant, resource, note string) {
	t.Helper()
	if err := s.Add(context.Background(), tenant, WatchEntry{
		Resource: resource, Kind: "asn", Note: note, AddedBy: "u@" + tenant,
	}); err != nil {
		t.Fatalf("Add(%s,%s): %v", tenant, resource, err)
	}
}

func resources(rows []WatchEntry) []string {
	out := make([]string, 0, len(rows))
	for _, e := range rows {
		out = append(out, e.Resource)
	}
	return out
}

// A tenant reads its OWN rows and nothing else — the §3a rule-4 property, held
// by the store rather than by whoever calls it.
func TestWatchFileStoreListIsOwnOnly(t *testing.T) {
	s, _ := newTestWatchStore(t)
	ctx := context.Background()
	mustAdd(t, s, "acme", "AS64500", "acme peering")
	mustAdd(t, s, "globex", "AS64501", "globex peering")

	acme, err := s.List(ctx, "acme", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := resources(acme); len(got) != 1 || got[0] != "AS64500" {
		t.Fatalf("CROSS-TENANT LEAK: acme sees %v, want [AS64500]", got)
	}
	if acme[0].AddedBy != "u@acme" {
		t.Fatalf("added_by = %q, want u@acme", acme[0].AddedBy)
	}
	gx, err := s.List(ctx, "globex", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := resources(gx); len(got) != 1 || got[0] != "AS64501" {
		t.Fatalf("CROSS-TENANT LEAK: globex sees %v, want [AS64501]", got)
	}
}

// The ONLY cross-tenant read is the platform owner's explicit cross=true — the
// mirror of the Postgres '*' RLS scope. A scope-less caller (cross=false with
// no tenant) reads NOTHING, never everything.
func TestWatchFileStoreCrossReadIsTheOnlyWayOut(t *testing.T) {
	s, _ := newTestWatchStore(t)
	ctx := context.Background()
	mustAdd(t, s, "acme", "AS64500", "")
	mustAdd(t, s, "globex", "AS64501", "")

	all, err := s.List(ctx, "global", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("platform-owner cross list = %v, want both rows", resources(all))
	}
	for _, tenant := range []string{"", "   ", "*", " * "} {
		rows, err := s.List(ctx, tenant, false)
		if err != nil {
			t.Fatalf("List(%q) errored instead of reading nothing: %v", tenant, err)
		}
		if len(rows) != 0 {
			t.Fatalf("DEFAULT-OPEN: List(%q, cross=false) returned %v", tenant, resources(rows))
		}
	}
}

// Writes fail closed on a non-concrete tenant, so no future caller can
// reintroduce a wildcard write (the bgpWatchTenant precedent).
func TestWatchFileStoreWritesRefuseNonConcreteTenant(t *testing.T) {
	s, _ := newTestWatchStore(t)
	ctx := context.Background()
	for _, tenant := range []string{"", "  ", "*", " * "} {
		if err := s.Add(ctx, tenant, WatchEntry{Resource: "AS1", Kind: "asn"}); err == nil {
			t.Errorf("Add(%q) accepted a non-concrete tenant", tenant)
		}
		if _, err := s.Delete(ctx, tenant, "AS1"); err == nil {
			t.Errorf("Delete(%q) accepted a non-concrete tenant", tenant)
		}
	}
	if rows, _ := s.List(ctx, "acme", false); len(rows) != 0 {
		t.Fatalf("refused writes still landed somewhere: %v", resources(rows))
	}
}

// Deleting a resource ANOTHER tenant watches is "not found", never a deletion.
func TestWatchFileStoreCrossTenantDeleteIsNotFound(t *testing.T) {
	s, _ := newTestWatchStore(t)
	ctx := context.Background()
	mustAdd(t, s, "acme", "AS64500", "")

	found, err := s.Delete(ctx, "globex", "AS64500")
	if err != nil {
		t.Fatalf("cross delete errored: %v", err)
	}
	if found {
		t.Fatal("CROSS-TENANT DELETE: globex removed acme's row")
	}
	if rows, _ := s.List(ctx, "acme", false); len(rows) != 1 {
		t.Fatalf("acme's row is gone after a foreign delete: %v", resources(rows))
	}
	if found, err := s.Delete(ctx, "acme", "AS64500"); err != nil || !found {
		t.Fatalf("acme deleting its own row: found=%v err=%v", found, err)
	}
}

// Re-adding a resource updates ONLY the note — the ON CONFLICT DO UPDATE SET
// note parity. created_at is the page's "watched since" and must not reset.
func TestWatchFileStoreUpsertKeepsCreatedAt(t *testing.T) {
	s, _ := newTestWatchStore(t)
	ctx := context.Background()
	mustAdd(t, s, "acme", "AS64500", "first")
	first, _ := s.List(ctx, "acme", false)
	if len(first) != 1 || first[0].CreatedAt.IsZero() {
		t.Fatalf("first add did not stamp created_at: %+v", first)
	}
	if err := s.Add(ctx, "acme", WatchEntry{Resource: "AS64500", Kind: "asn", Note: "second", AddedBy: "someone-else"}); err != nil {
		t.Fatal(err)
	}
	after, _ := s.List(ctx, "acme", false)
	if len(after) != 1 {
		t.Fatalf("upsert duplicated the row: %v", resources(after))
	}
	if after[0].Note != "second" {
		t.Fatalf("note = %q, want the updated one", after[0].Note)
	}
	if !after[0].CreatedAt.Equal(first[0].CreatedAt) {
		t.Fatal("upsert reset created_at — the watch would look newly added")
	}
	if after[0].AddedBy != "u@acme" {
		t.Fatalf("upsert rewrote added_by to %q — PG keeps the original", after[0].AddedBy)
	}
}

// Rows survive a restart, and they come back in the SAME tenant bucket.
func TestWatchFileStorePersistsPerTenant(t *testing.T) {
	s, path := newTestWatchStore(t)
	ctx := context.Background()
	mustAdd(t, s, "acme", "203.0.113.0/24", "dc egress")
	mustAdd(t, s, "globex", "198.51.100.0/24", "")

	raw, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("watchlist file not written: %v", err)
	}
	var onDisk map[string][]WatchEntry
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("watchlist file is not tenant-keyed JSON: %v (%s)", err, raw)
	}
	if len(onDisk["acme"]) != 1 || len(onDisk["globex"]) != 1 {
		t.Fatalf("on-disk buckets = %v, want one row each", onDisk)
	}

	reopened := NewWatchFileStore(path)
	if err := reopened.LoadErr(); err != nil {
		t.Fatalf("reload reported corruption: %v", err)
	}
	rows, _ := reopened.List(ctx, "acme", false)
	if got := resources(rows); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("after reload acme sees %v", got)
	}
	if rows, _ := reopened.List(ctx, "globex", false); len(rows) != 1 || rows[0].Resource != "198.51.100.0/24" {
		t.Fatalf("after reload globex sees %v", resources(rows))
	}
}

// A corrupt file starts EMPTY and SAYS SO — never silently "no watches".
func TestWatchFileStoreCorruptFileIsLoudAndEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bgp_watchlist.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewWatchFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("a corrupt watchlist loaded silently — the operator would never know")
	}
	if rows, _ := s.List(context.Background(), "acme", false); len(rows) != 0 {
		t.Fatalf("corrupt load produced rows: %v", resources(rows))
	}
}

// A persisted "" / "*" bucket is not a tenant's data and must never be served.
func TestWatchFileStoreDropsNonConcreteBucketsOnLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bgp_watchlist.json")
	body, err := json.Marshal(map[string][]WatchEntry{
		"*":    {{Resource: "AS64500", Kind: "asn"}},
		"acme": {{Resource: "AS64501", Kind: "asn"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewWatchFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("a wildcard bucket was dropped SILENTLY")
	}
	all, _ := s.List(context.Background(), "", true)
	if got := resources(all); len(got) != 1 || got[0] != "AS64501" {
		t.Fatalf("wildcard bucket survived the load: %v", got)
	}
}

// Untrusted rows are bounded and validated at the store, not only at the
// handler: an unknown kind or an empty resource is DROPPED, a long note clipped
// on a rune boundary.
func TestWatchFileStoreBoundsAndValidatesRows(t *testing.T) {
	s, _ := newTestWatchStore(t)
	ctx := context.Background()
	for _, bad := range []WatchEntry{
		{Resource: "", Kind: "asn"},
		{Resource: "AS1", Kind: ""},
		{Resource: "AS1", Kind: "sql"},
	} {
		if err := s.Add(ctx, "acme", bad); err == nil {
			t.Errorf("Add accepted an invalid row: %+v", bad)
		}
	}
	long := strings.Repeat("a", MaxWatchNoteBytes-1) + "🌍"
	if err := s.Add(ctx, "acme", WatchEntry{Resource: "AS64500", Kind: "asn", Note: long}); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.List(ctx, "acme", false)
	if len(rows) != 1 {
		t.Fatalf("want the one valid row, got %v", resources(rows))
	}
	if n := len(rows[0].Note); n > MaxWatchNoteBytes {
		t.Fatalf("note stored at %d bytes, cap is %d", n, MaxWatchNoteBytes)
	}
	if !utf8.ValidString(rows[0].Note) {
		t.Fatal("clip split a rune — the stored note is not valid UTF-8")
	}
}

// The per-tenant register is BOUNDED (§9): the evaluator does one outbound
// measurement per watched prefix per pass.
func TestWatchFileStoreIsBounded(t *testing.T) {
	s, _ := newTestWatchStore(t)
	ctx := context.Background()
	for i := 0; i < MaxWatchEntriesPerTenant; i++ {
		mustAdd(t, s, "acme", "AS"+strconv.Itoa(64500+i), "")
	}
	if err := s.Add(ctx, "acme", WatchEntry{Resource: "AS9999999", Kind: "asn"}); err == nil {
		t.Fatal("the watchlist grew past its bound")
	}
	// A FULL tenant can still update an existing row (an upsert adds nothing).
	if err := s.Add(ctx, "acme", WatchEntry{Resource: "AS64500", Kind: "asn", Note: "still editable"}); err != nil {
		t.Fatalf("upsert refused on a full watchlist: %v", err)
	}
	// And another tenant's budget is its own.
	mustAdd(t, s, "globex", "AS64500", "")
}

// Newest-first, matching the Postgres ORDER BY created_at DESC, and stable
// across restarts (map iteration is not).
func TestWatchFileStoreListIsNewestFirstAndStable(t *testing.T) {
	s, _ := newTestWatchStore(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	for i, res := range []string{"AS1", "AS2", "AS3"} {
		if err := s.Add(ctx, "acme", WatchEntry{
			Resource: res, Kind: "asn", CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}
	got := resources(mustList(t, s, "acme"))
	want := []string{"AS3", "AS2", "AS1"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v (newest first)", got, want)
		}
	}
	for i := 0; i < 5; i++ {
		if next := resources(mustList(t, s, "acme")); strings.Join(next, ",") != strings.Join(got, ",") {
			t.Fatalf("List order is not stable: %v then %v", got, next)
		}
	}
}

func mustList(t *testing.T, s *WatchFileStore, tenant string) []WatchEntry {
	t.Helper()
	rows, err := s.List(context.Background(), tenant, false)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}
