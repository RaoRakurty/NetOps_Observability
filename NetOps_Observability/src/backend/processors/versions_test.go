package processors

// versions_test.go — the history/rollback contract (review test-gap: versioning
// had ZERO coverage on either backend). The invariants under test are the ones
// an auditor would ask about: history is append-only, a rollback is itself
// recorded, retention is bounded, and another tenant's history is invisible.

import (
	"context"
	"path/filepath"
	"testing"
)

func newRule(t *testing.T, tenant, field string) Processor {
	t.Helper()
	r := Processor{TenantID: tenant, Lane: "syslog", Type: TypeDropField, Field: field, Enabled: true}
	if err := r.Validate(); err != nil {
		t.Fatalf("fixture must validate: %v", err)
	}
	return r
}

func TestVersionHistoryIsAppendOnly(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore(filepath.Join(t.TempDir(), "p.json"))

	created, err := s.Create(ctx, "acme", false, newRule(t, "acme", "secret_v1"))
	if err != nil {
		t.Fatal(err)
	}
	if created.Version != 1 {
		t.Fatalf("a new processor starts at v1, got %d", created.Version)
	}

	edit := created
	edit.Field = "secret_v2"
	updated, found, err := s.Update(ctx, "acme", false, created.ID, edit)
	if err != nil || !found {
		t.Fatalf("update: %v found=%v", err, found)
	}
	if updated.Version != 2 {
		t.Fatalf("an edit bumps the version, got %d", updated.Version)
	}

	vs, found, err := s.ListVersions(ctx, "acme", false, created.ID)
	if err != nil || !found {
		t.Fatalf("history: %v found=%v", err, found)
	}
	if len(vs) != 2 || vs[0].Version != 2 || vs[1].Version != 1 {
		t.Fatalf("history is newest-first and complete: %+v", vs)
	}
	if vs[0].ChangeKind != "updated" || vs[1].ChangeKind != "created" {
		t.Fatalf("each entry records WHAT happened: %+v", vs)
	}
	if vs[1].Config.Field != "secret_v1" {
		t.Fatalf("the v1 snapshot must preserve the ORIGINAL config, got %q", vs[1].Config.Field)
	}

	// Rollback writes the old config FORWARD as a new version — an audit trail
	// you can rewind is not an audit trail.
	rolled, found, err := s.Rollback(ctx, "acme", false, created.ID, 1, "auditor")
	if err != nil || !found {
		t.Fatalf("rollback: %v found=%v", err, found)
	}
	if rolled.Version != 3 {
		t.Fatalf("rollback appends (v3), it does not rewind: got v%d", rolled.Version)
	}
	if rolled.Field != "secret_v1" {
		t.Fatalf("rollback must restore the old config, got %q", rolled.Field)
	}
	vs, _, _ = s.ListVersions(ctx, "acme", false, created.ID)
	if len(vs) != 3 || vs[0].ChangeKind != "rolled_back" || vs[0].ChangedBy != "auditor" {
		t.Fatalf("the rollback itself must be recorded, with its actor: %+v", vs[0])
	}

	// Rolling back to a version that does not exist is a miss, not a mutation.
	if _, found, _ := s.Rollback(ctx, "acme", false, created.ID, 99, "auditor"); found {
		t.Fatal("rollback to an unknown version must not succeed")
	}
}

func TestVersionHistoryIsTenantScoped(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore(filepath.Join(t.TempDir(), "p.json"))
	a, _ := s.Create(ctx, "acme", false, newRule(t, "acme", "a"))
	b, _ := s.Create(ctx, "globex", false, newRule(t, "globex", "b"))

	if _, found, _ := s.ListVersions(ctx, "acme", false, b.ID); found {
		t.Fatal("TENANT LEAK: acme read globex's processor history")
	}
	if _, found, _ := s.Rollback(ctx, "acme", false, b.ID, 1, "x"); found {
		t.Fatal("TENANT LEAK: acme rolled back globex's processor")
	}
	// The owner's own history still resolves, and a platform principal sees both.
	if _, found, _ := s.ListVersions(ctx, "globex", false, b.ID); !found {
		t.Fatal("owner must see its own history")
	}
	if _, found, _ := s.ListVersions(ctx, "", true, a.ID); !found {
		t.Fatal("platform principal must see any history")
	}
}

func TestVersionRetentionIsBounded(t *testing.T) {
	ctx := context.Background()
	s := NewFileStore(filepath.Join(t.TempDir(), "p.json"))
	r, err := s.Create(ctx, "acme", false, newRule(t, "acme", "f0"))
	if err != nil {
		t.Fatal(err)
	}
	// Edit well past the cap; retention must hold (§9 bounded stores).
	for i := 1; i <= MaxVersionsPerProcessor+10; i++ {
		edit := r
		edit.Description = "edit"
		if _, found, err := s.Update(ctx, "acme", false, r.ID, edit); err != nil || !found {
			t.Fatalf("edit %d: %v found=%v", i, err, found)
		}
	}
	vs, _, _ := s.ListVersions(ctx, "acme", false, r.ID)
	if len(vs) > MaxVersionsPerProcessor {
		t.Fatalf("history must stay bounded at %d, got %d", MaxVersionsPerProcessor, len(vs))
	}
	// The NEWEST entries are the ones kept.
	if vs[0].Version != MaxVersionsPerProcessor+11 {
		t.Fatalf("retention must evict the OLDEST, keeping the newest: top is v%d", vs[0].Version)
	}
}
