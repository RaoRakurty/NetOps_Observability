// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// store_test.go — the store half of §3a rule 4: isolation lives in the STORE,
// so a lookup for tenant A can only ever walk A's bucket. The HTTP half is
// src/backend/dem_experience_isolation_test.go.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newJourney(tenant, name string) JourneyDefinition {
	j := checkoutJourney()
	j.ID, j.TenantID, j.Name = "", tenant, name
	return j
}

func TestFileStoreScopesByTenant(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore(filepath.Join(t.TempDir(), "exp.json"))

	a, err := s.CreateJourney(ctx, newJourney("acme", "A checkout"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreateJourney(ctx, newJourney("globex", "B checkout"))
	if err != nil {
		t.Fatal(err)
	}

	list, err := s.ListJourneys(ctx, "acme")
	if err != nil || len(list) != 1 || list[0].ID != a.ID {
		t.Fatalf("acme sees %+v (err %v)", list, err)
	}
	if _, err := s.GetJourney(ctx, "acme", b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("acme read globex's journey: %v", err)
	}
	if _, err := s.UpdateJourney(ctx, "acme", b.ID, newJourney("acme", "hijack")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("acme updated globex's journey: %v", err)
	}
	if err := s.DeleteJourney(ctx, "acme", b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("acme deleted globex's journey: %v", err)
	}

	// A scopeless read returns NOTHING rather than everything — the same answer
	// an empty RLS GUC gives on the Postgres twin.
	for _, scope := range []string{"", "*", "   "} {
		if got, _ := s.ListJourneys(ctx, scope); len(got) != 0 {
			t.Fatalf("a scopeless read (%q) returned %d journeys", scope, len(got))
		}
	}
}

func TestFileStoreChangesAreImmutableAndScoped(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore("")
	ch := ChangeEvent{
		TenantID: "acme", Type: ChangeConfig, Object: "sw-1", Summary: "vlan edit",
		Provenance: prov(SourceConfigDrift, -5*time.Minute),
	}
	first, err := s.RecordChange(ctx, ch)
	if err != nil {
		t.Fatal(err)
	}
	// Replaying the same id must NOT rewrite the recorded fact.
	again := first
	again.Summary = "rewritten"
	got, err := s.RecordChange(ctx, again)
	if err != nil {
		t.Fatal(err)
	}
	if got.Summary != "vlan edit" {
		t.Fatalf("a replayed change rewrote history: %q", got.Summary)
	}
	if list, _ := s.ListChanges(ctx, "globex", ChangeQuery{}); len(list) != 0 {
		t.Fatalf("another tenant saw the change: %+v", list)
	}
}

// writeFile is a local helper: the store's own persistence goes through the
// platform's Save, and a test that needs a DELIBERATELY corrupt file has to
// write it directly.
func writeFile(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }

func TestFileStoreSurvivesACorruptFileAndSaysSo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exp.json")
	if err := writeFile(path, []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	s := NewFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("a corrupt store loaded silently — an empty table that is really a read failure is the worst of both")
	}
	if got, _ := s.ListJourneys(context.Background(), "acme"); len(got) != 0 {
		t.Fatalf("a corrupt store served rows: %+v", got)
	}
}

func TestFileStoreDropsANonConcreteTenantBucket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exp.json")
	if err := writeFile(path, []byte(`{"journeys":{"*":[{"id":"jny-x","name":"n"}]}}`)); err != nil {
		t.Fatal(err)
	}
	s := NewFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("a wildcard tenant bucket was loaded without complaint")
	}
	if got, _ := s.ListJourneys(context.Background(), "acme"); len(got) != 0 {
		t.Fatalf("a wildcard bucket became a tenant's data: %+v", got)
	}
}

func TestIDShapesAreCheckedBeforeAnyLookup(t *testing.T) {
	for _, bad := range []string{"", "jny-", "../../etc/passwd", "jny-ZZZZ", "exp-0000"} {
		if ValidJourneyID(bad) {
			t.Fatalf("%q was accepted as a journey id", bad)
		}
	}
	if !ValidJourneyID("jny-" + "0123456789abcdef0123456789abcdef") {
		t.Fatal("a well-formed journey id was refused")
	}
}

// TestRecordChangeDoesNotCorruptTheChangeLogWhenTheFlushFails: RecordChange
// appended to the live slice, trimmed it, and put the SAVED SLICE HEADER back
// when the flush failed. That is not a rollback. trimChanges sorts in place, and
// an append with spare capacity writes in place, so both of them mutate the very
// array the saved header points into: restoring the header restores a MUTATED
// array under the old length. Three changes leave len 3 cap 4, so a fourth
// append writes into the spare slot, the sort moves it to the front, and the
// restored log reads [c4 c3 c2]. The change the producer was told FAILED is in
// the log, and c1, which had been persisted, is gone.
//
// It does not stay in memory. The producer retries after its 500, RecordChange
// mints a fresh id, and the next successful flush writes the whole map, so the
// phantom and the deletion both become durable. The disk is therefore the
// assertion that matters (§10, no silent failures).
func TestRecordChangeDoesNotCorruptTheChangeLogWhenTheFlushFails(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "exp.json")
	s := NewFileStore(path)

	// Three, deliberately: a nil slice grown by three appends is len 3 cap 4, so
	// the fourth append has a spare slot to scribble into.
	for i := 0; i < 3; i++ {
		if _, err := s.RecordChange(ctx, ChangeEvent{
			TenantID: "acme", Type: ChangeConfig,
			Object:     fmt.Sprintf("sw-%d", i+1),
			Summary:    fmt.Sprintf("change %d", i+1),
			Provenance: prov(SourceConfigDrift, time.Duration(i-30)*time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Break the write. The store's file now has a FILE for a parent directory,
	// so the atomic write cannot create its temp file — the same shape as a full
	// or read-only volume, without needing either.
	s.path = filepath.Join(path, "exp.json")
	if _, err := s.RecordChange(ctx, ChangeEvent{
		TenantID: "acme", Type: ChangeConfig,
		Object: "sw-4-phantom", Summary: "the change that was refused",
		Provenance: prov(SourceConfigDrift, -1*time.Minute),
	}); err == nil {
		t.Fatal("RecordChange must report a flush it could not complete")
	}

	assertLog := func(where string, got []ChangeEvent, want []string) {
		t.Helper()
		have := make([]string, 0, len(got))
		for _, c := range got {
			if c.Object == "sw-4-phantom" {
				t.Errorf("PHANTOM %s: the change RecordChange refused is in the log", where)
			}
			have = append(have, c.Object)
		}
		if strings.Join(have, ",") != strings.Join(want, ",") {
			t.Errorf("CHANGE LOG CORRUPT %s: log reads [%s], want [%s]",
				where, strings.Join(have, " "), strings.Join(want, " "))
		}
	}

	inMem, err := s.ListChanges(ctx, "acme", ChangeQuery{})
	if err != nil {
		t.Fatal(err)
	}
	assertLog("in memory", inMem, []string{"sw-3", "sw-2", "sw-1"})

	// The next successful write is where an in-memory corruption becomes
	// permanent: it serialises the whole map as it then stands.
	s.path = path
	if _, err := s.RecordChange(ctx, ChangeEvent{
		TenantID: "acme", Type: ChangeConfig,
		Object: "sw-5", Summary: "a later change that does persist",
		Provenance: prov(SourceConfigDrift, -30*time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	reloaded := NewFileStore(path)
	if err := reloaded.LoadErr(); err != nil {
		t.Fatalf("the store wrote a file it cannot read back: %v", err)
	}
	onDisk, err := reloaded.ListChanges(ctx, "acme", ChangeQuery{})
	if err != nil {
		t.Fatal(err)
	}
	assertLog("on disk", onDisk, []string{"sw-5", "sw-3", "sw-2", "sw-1"})
}

// An UNREADABLE store file is not an ABSENT one. Folding the two together
// starts the store empty with nothing logged, and the first write then renames
// a temp file over a file whose contents were never read — every tenant's
// journeys, changes and promotions gone, silently. The load must say so, and
// the write must refuse.
func TestUnreadableStoreFileIsNotAnEmptyOneAndIsNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exp.json")
	seed := NewFileStore(path)
	kept, err := seed.CreateJourney(context.Background(), newJourney("acme", "Checkout"))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seeded file: %v", err)
	}

	// A permissions change is all it takes. The directory stays writable, so
	// the atomic rename in the next write would succeed.
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, err := os.ReadFile(path); err == nil {
		t.Skip("this environment can read a 0000 file (running as root?), so the case cannot be staged")
	}

	s := NewFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("an unreadable store loaded silently — the operator sees an empty table with no reason, and the next write destroys the file")
	}

	// The write must REFUSE while the file's real contents are unknown.
	if _, err := s.CreateJourney(context.Background(), newJourney("acme", "New")); err == nil {
		t.Fatal("a write was accepted over a store whose file could not be read")
	}
	if _, err := s.RecordChange(context.Background(), ChangeEvent{
		TenantID: "acme", Type: ChangeConfig, Object: "sw-1", Summary: "vlan edit",
		Provenance: prov(SourceConfigDrift, -5*time.Minute),
	}); err == nil {
		t.Fatal("a change was recorded over a store whose file could not be read")
	}

	// And the file on disk must still hold what it held.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file after: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("the store file was rewritten while it could not be read:\nbefore %s\nafter  %s", before, after)
	}
	reopened := NewFileStore(path)
	if reopened.LoadErr() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.LoadErr())
	}
	got, gerr := reopened.GetJourney(context.Background(), "acme", kept.ID)
	if gerr != nil || got.Name != "Checkout" {
		t.Fatalf("the seeded journey did not survive: %v %+v", gerr, got)
	}
}

// A file that is ABSENT is still just an empty store, with nothing reported.
func TestAbsentStoreFileStaysAnEmptyStore(t *testing.T) {
	s := NewFileStore(filepath.Join(t.TempDir(), "nothing-here.json"))
	if err := s.LoadErr(); err != nil {
		t.Fatalf("a store that was never written reported %v", err)
	}
	if _, err := s.CreateJourney(context.Background(), newJourney("acme", "First")); err != nil {
		t.Fatalf("the first write on a fresh store failed: %v", err)
	}
}
