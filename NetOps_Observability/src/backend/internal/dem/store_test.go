// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dem

// store_test.go — the file catalogue, with the isolation properties CLAUDE.md
// §3a rule 5 requires proven AT THE STORE (the HTTP half lives in the root
// package's dem_isolation_test.go, driven through the real router).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTarget(tenant, name, host string) Target {
	return Target{TenantID: tenant, Name: name, Kind: KindICMP, Host: host, Site: "dc1", App: "core"}
}

func mustCreate(t *testing.T, s Catalogue, in Target) Target {
	t.Helper()
	out, err := s.Create(context.Background(), in)
	if err != nil {
		t.Fatalf("Create(%s): %v", in.Name, err)
	}
	return out
}

func TestFileStoreCRUD(t *testing.T) {
	s := NewFileStore("")
	ctx := context.Background()
	a := mustCreate(t, s, newTarget("acme", "spine1", "10.0.0.1"))
	if !strings.HasPrefix(a.ID, "dem-") || a.CreatedAt.IsZero() || a.UpdatedAt.IsZero() {
		t.Fatalf("create did not stamp identity/lifecycle: %+v", a)
	}

	got, err := s.Get(ctx, "acme", a.ID)
	if err != nil || got.ID != a.ID {
		t.Fatalf("Get: %v %+v", err, got)
	}

	paused := true
	name := "spine1-renamed"
	up, err := s.Update(ctx, "acme", a.ID, Patch{Paused: &paused, Name: &name})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !up.Paused || up.Name != name {
		t.Fatalf("patch not applied: %+v", up)
	}
	if !up.UpdatedAt.After(a.UpdatedAt) && !up.UpdatedAt.Equal(a.UpdatedAt) {
		t.Fatalf("updated_at went backwards")
	}
	if up.CreatedAt != a.CreatedAt {
		t.Fatalf("created_at was rewritten")
	}

	if err := s.Delete(ctx, "acme", a.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "acme", a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete: %v", err)
	}
}

// The kind is IMMUTABLE: changing it would orphan every series already recorded
// under the target's id, so a patch must not be able to do it.
func TestUpdateCannotChangeKindOrOwner(t *testing.T) {
	s := NewFileStore("")
	a := mustCreate(t, s, newTarget("acme", "x", "10.0.0.1"))
	host := "10.0.0.9"
	up, err := s.Update(context.Background(), "acme", a.ID, Patch{Host: &host})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if up.Kind != KindICMP || up.TenantID != "acme" || up.ID != a.ID {
		t.Fatalf("identity mutated: %+v", up)
	}
}

// §3a rule 1: a tenant may never reach another tenant's row, and a cross-tenant
// id must be indistinguishable from an absent one.
func TestFileStoreTenantIsolation(t *testing.T) {
	s := NewFileStore("")
	ctx := context.Background()
	a := mustCreate(t, s, newTarget("acme", "acme-target", "10.0.0.1"))
	b := mustCreate(t, s, newTarget("globex", "globex-target", "10.0.0.2"))

	list, err := s.List(ctx, "acme")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].ID != a.ID {
		t.Fatalf("acme sees %d rows: %+v", len(list), list)
	}

	if _, err := s.Get(ctx, "acme", b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant Get returned %v (must be ErrNotFound)", err)
	}
	paused := true
	if _, err := s.Update(ctx, "acme", b.ID, Patch{Paused: &paused}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant Update returned %v", err)
	}
	if err := s.Delete(ctx, "acme", b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant Delete returned %v", err)
	}
	// …and the victim's row is still there.
	if _, err := s.Get(ctx, "globex", b.ID); err != nil {
		t.Fatalf("globex lost its row to a cross-tenant delete: %v", err)
	}
}

// A scopeless caller reads NOTHING (default-closed), which is what an empty RLS
// GUC does on the Postgres twin. It must never mean "everything".
func TestFileStoreScopelessReadsNothing(t *testing.T) {
	s := NewFileStore("")
	mustCreate(t, s, newTarget("acme", "x", "10.0.0.1"))
	for _, scope := range []string{"", "*", "   "} {
		list, err := s.List(context.Background(), scope)
		if err != nil {
			t.Fatalf("List(%q): %v", scope, err)
		}
		if len(list) != 0 {
			t.Fatalf("scopeless List(%q) returned %d rows", scope, len(list))
		}
	}
}

// ListAll is the projector's platform read and the ONLY cross-tenant path.
func TestListAllSeesEveryTenant(t *testing.T) {
	s := NewFileStore("")
	mustCreate(t, s, newTarget("acme", "a", "10.0.0.1"))
	mustCreate(t, s, newTarget("globex", "b", "10.0.0.2"))
	all, err := s.ListAll(context.Background())
	if err != nil || len(all) != 2 {
		t.Fatalf("ListAll: %v %d", err, len(all))
	}
}

func TestCreateRefusesAWildcardOwner(t *testing.T) {
	s := NewFileStore("")
	for _, tenant := range []string{"", "*"} {
		if _, err := s.Create(context.Background(), newTarget(tenant, "x", "h")); err == nil {
			t.Fatalf("Create with tenant %q was accepted", tenant)
		}
	}
}

func TestPerTenantCap(t *testing.T) {
	s := NewFileStore("")
	s.rows["acme"] = map[string]Target{}
	for i := 0; i < MaxTargetsPerTenant; i++ {
		s.rows["acme"][string(rune('a'+i%26))+string(rune(i))] = Target{}
	}
	if _, err := s.Create(context.Background(), newTarget("acme", "one-too-many", "10.0.0.1")); !errors.Is(err, ErrCatalogueFull) {
		t.Fatalf("cap not enforced: %v", err)
	}
}

// Persistence round-trips through the platform kv seam, and a corrupt file
// starts EMPTY while SAYING so — it must never look like a catalogue a tenant
// never wrote.
func TestPersistenceAndCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dem_targets.json")
	s := NewFileStore(path)
	a := mustCreate(t, s, newTarget("acme", "spine1", "10.0.0.1"))

	reopened := NewFileStore(path)
	if err := reopened.LoadErr(); err != nil {
		t.Fatalf("clean reopen reported %v", err)
	}
	got, err := reopened.Get(context.Background(), "acme", a.ID)
	if err != nil || got.Name != "spine1" {
		t.Fatalf("row did not survive a reopen: %v %+v", err, got)
	}

	if err := writeFile(path, []byte("{ not json")); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	broken := NewFileStore(path)
	if broken.LoadErr() == nil {
		t.Fatal("a corrupt catalogue loaded silently — the operator would see an empty table with no reason")
	}
	list, _ := broken.List(context.Background(), "acme")
	if len(list) != 0 {
		t.Fatalf("corrupt store served %d rows", len(list))
	}
}

// A persisted bucket keyed by "" or "*" is not any tenant's data and must never
// become some tenant's data.
func TestNonConcreteBucketOnDiskIsDropped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dem_targets.json")
	if err := writeFile(path, []byte(`{"*":[{"id":"dem-1","tenant_id":"*","name":"x","kind":"icmp","host":"10.0.0.1","interval_sec":60}]}`)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s := NewFileStore(path)
	if s.LoadErr() == nil {
		t.Fatal("a wildcard bucket loaded without complaint")
	}
	all, _ := s.ListAll(context.Background())
	if len(all) != 0 {
		t.Fatalf("wildcard bucket became %d real rows", len(all))
	}
}

// An UNREADABLE catalogue file is not an ABSENT one. Folding the two together
// starts the catalogue empty with nothing logged, and the first write then
// renames a temp file over a file whose contents were never read — every
// tenant's targets gone, silently. The load must say so, and the write must
// refuse.
func TestUnreadableCatalogueFileIsNotAnEmptyOneAndIsNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dem_targets.json")
	seed := NewFileStore(path)
	kept := mustCreate(t, seed, newTarget("acme", "spine1", "10.0.0.1"))
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
		t.Fatal("an unreadable catalogue loaded silently — the operator sees an empty table with no reason, and the next write destroys the file")
	}
	if _, err := s.Create(context.Background(), newTarget("acme", "spine2", "10.0.0.2")); err == nil {
		t.Fatal("a write was accepted over a catalogue whose file could not be read")
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file after: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("the catalogue file was rewritten while it could not be read:\nbefore %s\nafter  %s", before, after)
	}
	reopened := NewFileStore(path)
	if reopened.LoadErr() != nil {
		t.Fatalf("the repaired file no longer loads: %v", reopened.LoadErr())
	}
	got, gerr := reopened.Get(context.Background(), "acme", kept.ID)
	if gerr != nil || got.Name != "spine1" {
		t.Fatalf("the seeded target did not survive: %v %+v", gerr, got)
	}
}

// A file that is ABSENT is still just an empty catalogue, with nothing reported.
func TestAbsentCatalogueFileStaysAnEmptyCatalogue(t *testing.T) {
	s := NewFileStore(filepath.Join(t.TempDir(), "nothing-here.json"))
	if err := s.LoadErr(); err != nil {
		t.Fatalf("a catalogue that was never written reported %v", err)
	}
	if _, err := s.Create(context.Background(), newTarget("acme", "first", "10.0.0.1")); err != nil {
		t.Fatalf("the first write on a fresh catalogue failed: %v", err)
	}
}

// overCapFile writes a catalogue file holding one tenant bucket with n targets.
func overCapFile(t *testing.T, path, tenant string, n int) {
	t.Helper()
	list := make([]Target, 0, n)
	for i := 0; i < n; i++ {
		list = append(list, Target{
			TenantID: tenant, ID: fmt.Sprintf("dem-%04d", i), Name: fmt.Sprintf("tgt-%04d", i),
			Kind: KindICMP, Host: "10.0.0.1", IntervalSec: 60,
		})
	}
	raw, err := json.Marshal(map[string][]Target{tenant: list})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := writeFile(path, raw); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// An OVER-CAP tenant bucket was truncated at load with a bare break: no
// loadErr, nothing logged, the excess targets simply not there — and because
// the store then flushes the WHOLE catalogue on the next write, the truncation
// became durable. ImportFile refuses the identical condition loudly and names
// the tenant, so the two paths disagreed about the same file (review
// 2026-09-08, 3.2-17).
func TestOverCapCatalogueFileIsLoudAndIsNeverOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dem_targets.json")
	const over = MaxTargetsPerTenant + 7
	overCapFile(t, path, "acme", over)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seeded file: %v", err)
	}

	s := NewFileStore(path)
	le := s.LoadErr()
	if le == nil {
		t.Fatal("an over-cap catalogue loaded silently — the excess targets are unmeasured and nothing said so")
	}
	if !errors.Is(le, ErrCatalogueOverCap) {
		t.Errorf("load error %v does not carry ErrCatalogueOverCap", le)
	}
	for _, want := range []string{"acme", fmt.Sprintf("%d", over), fmt.Sprintf("%d", MaxTargetsPerTenant)} {
		if !strings.Contains(le.Error(), want) {
			t.Errorf("the load error does not name %q, so the operator cannot act on it: %v", want, le)
		}
	}

	// And the truncation must not become durable: every write is refused while
	// the file still holds targets this process never loaded.
	if _, err := s.Create(context.Background(), newTarget("acme", "one-more", "10.0.0.2")); !errors.Is(err, ErrCatalogueOverCap) {
		t.Fatalf("a write over a truncated catalogue was accepted (err %v) — the next flush persists the truncation", err)
	}
	if err := s.Delete(context.Background(), "acme", "dem-0000"); !errors.Is(err, ErrCatalogueOverCap) {
		t.Fatalf("a delete over a truncated catalogue was accepted: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file after: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("the catalogue file was rewritten while it held targets the store never loaded")
	}
}

// A bucket exactly AT the cap is a legal catalogue: it loads clean and writes.
func TestCatalogueFileExactlyAtTheCapLoadsClean(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dem_targets.json")
	overCapFile(t, path, "acme", MaxTargetsPerTenant)
	s := NewFileStore(path)
	if err := s.LoadErr(); err != nil {
		t.Fatalf("a catalogue exactly at the cap reported %v", err)
	}
	list, err := s.List(context.Background(), "acme")
	if err != nil || len(list) != MaxTargetsPerTenant {
		t.Fatalf("loaded %d rows (err %v), want %d", len(list), err, MaxTargetsPerTenant)
	}
	// The per-tenant cap still refuses a NEW target, as it always did.
	if _, err := s.Create(context.Background(), newTarget("acme", "one-too-many", "10.0.0.2")); !errors.Is(err, ErrCatalogueFull) {
		t.Fatalf("cap not enforced after a full load: %v", err)
	}
}
