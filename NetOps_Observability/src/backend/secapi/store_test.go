package secapi

// store_test.go — the CLAUDE.md §3a rule 4 proof for the file backend: the
// tenant filter lives IN the store, so a handler bug cannot turn a scoped read
// into a cross-tenant one. (The Postgres backend's equivalent proof is the
// FORCE-RLS test in package backend, gated on DATABASE_URL_TEST.)

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func seedView(t *testing.T, s Store, tenant, name string) SavedView {
	t.Helper()
	v, err := s.AddView(context.Background(), tenant, false, SavedView{
		TenantID: tenant, Name: name,
		Filters:   json.RawMessage(`{"severity":"high"}`),
		CreatedBy: "seed@" + tenant,
	})
	if err != nil {
		t.Fatalf("seed view %s/%s: %v", tenant, name, err)
	}
	return v
}

func TestFileStoreViewsAreOwnOnly(t *testing.T) {
	s := NewFileStore("")
	mine := seedView(t, s, "acme", "critical exposures")
	theirs := seedView(t, s, "globex", "their view")

	got, err := s.Views(context.Background(), "acme", false)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].ID != mine.ID {
		t.Fatalf("acme saw %d views %+v — want only its own", len(got), got)
	}
	for _, v := range got {
		if v.ID == theirs.ID || v.TenantID == "globex" {
			t.Fatal("TENANT LEAK: acme's saved-view list carried globex's row")
		}
	}

	// The platform owner (cross) sees both — that is the cross-tenant flag
	// doing its job, and the ONLY way another tenant's row is ever visible.
	all, err := s.Views(context.Background(), "global", true)
	if err != nil {
		t.Fatalf("cross list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("cross-tenant list = %d views, want 2", len(all))
	}
}

func TestFileStoreCrossTenantDeleteIsNotFound(t *testing.T) {
	s := NewFileStore("")
	theirs := seedView(t, s, "globex", "their view")

	found, err := s.DeleteView(context.Background(), "acme", false, theirs.ID)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if found {
		t.Fatal("CROSS-TENANT DELETE: acme removed globex's saved view")
	}
	// …and the row is still there for its owner.
	rows, err := s.Views(context.Background(), "globex", false)
	if err != nil || len(rows) != 1 {
		t.Fatalf("globex's view was destroyed by another tenant's delete: %v %+v", err, rows)
	}
	// A NONEXISTENT id answers identically, which is what makes the 404 above
	// non-revealing: the two cases are indistinguishable to the caller.
	if found, _ := s.DeleteView(context.Background(), "acme", false, "11111111-2222-4333-8444-555555555555"); found {
		t.Fatal("a nonexistent id reported found")
	}
}

func TestFileStoreRuleStatesAreOwnOnly(t *testing.T) {
	s := NewFileStore("")
	ctx := context.Background()
	cat := Catalog()
	if len(cat) < 2 {
		t.Fatalf("catalog is too small to test with (%d rules)", len(cat))
	}
	a, b := cat[0].RuleID, cat[1].RuleID

	if err := s.SetRuleStates(ctx, "acme", false, "acme", []RuleState{{RuleID: a, Enabled: false}}); err != nil {
		t.Fatalf("acme write: %v", err)
	}
	if err := s.SetRuleStates(ctx, "globex", false, "globex", []RuleState{{RuleID: b, Enabled: false}}); err != nil {
		t.Fatalf("globex write: %v", err)
	}

	states, err := s.RuleStates(ctx, "acme", false)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(states) != 1 {
		t.Fatalf("acme saw %d overrides %v — want only its own", len(states), states)
	}
	if _, leaked := states[b]; leaked {
		t.Fatal("TENANT LEAK: acme saw globex's rule override")
	}
	// Overlaying acme's state must not disable globex's rule for acme.
	applied := Apply(cat, states)
	for _, r := range applied {
		switch r.RuleID {
		case a:
			if r.Enabled {
				t.Errorf("rule %s should be disabled for acme", a)
			}
		case b:
			if !r.Enabled {
				t.Errorf("rule %s must stay enabled for acme (it is globex's override)", b)
			}
		}
	}
}

// TestFileStoreDefaultsRulesOn is the §5g honesty rule: an empty override table
// means the full shipped catalog runs. If "no row" ever came to mean "off", a
// tenant that never opened the page would see a clean security surface produced
// by running nothing at all.
func TestFileStoreDefaultsRulesOn(t *testing.T) {
	s := NewFileStore("")
	states, err := s.RuleStates(context.Background(), "acme", false)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(states) != 0 {
		t.Fatalf("a fresh tenant should hold no overrides, got %v", states)
	}
	for _, r := range Apply(Catalog(), states) {
		if !r.Enabled {
			t.Fatalf("rule %s defaulted to DISABLED — an unassessed tenant would read as clean", r.RuleID)
		}
	}
}

func TestFileStoreEnforcesViewLimitsAndUniqueNames(t *testing.T) {
	s := NewFileStore("")
	ctx := context.Background()
	seedView(t, s, "acme", "dup")
	if _, err := s.AddView(ctx, "acme", false, SavedView{TenantID: "acme", Name: "DUP"}); !errors.Is(err, ErrDuplicateView) {
		t.Fatalf("duplicate name (case-insensitive) = %v, want ErrDuplicateView", err)
	}
	// The same name in ANOTHER tenant is fine — uniqueness is per tenant.
	if _, err := s.AddView(ctx, "globex", false, SavedView{TenantID: "globex", Name: "dup"}); err != nil {
		t.Fatalf("same name in another tenant was refused: %v", err)
	}
}

func TestFileStorePersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "security_control_plane.json")
	s := NewFileStore(path)
	mine := seedView(t, s, "acme", "mine")
	rule := Catalog()[0].RuleID
	if err := s.SetRuleStates(context.Background(), "acme", false, "acme", []RuleState{{RuleID: rule, Enabled: false}}); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("state file was not written: %v", err)
	}

	// A fresh store over the same file must see the same rows — under the same
	// tenant, never widened.
	reloaded := NewFileStore(path)
	views, err := reloaded.Views(context.Background(), "acme", false)
	if err != nil || len(views) != 1 || views[0].ID != mine.ID {
		t.Fatalf("reload lost the view: %v %+v", err, views)
	}
	if other, _ := reloaded.Views(context.Background(), "globex", false); len(other) != 0 {
		t.Fatalf("RELOAD LEAK: globex saw %d of acme's views", len(other))
	}
	states, err := reloaded.RuleStates(context.Background(), "acme", false)
	if err != nil || states[rule] {
		t.Fatalf("reload lost the rule override: %v %v", err, states)
	}
}

// TestFileStoreDistinguishesMissingFromBroken is §10 as a test: a store file
// that has never been written is "nothing configured" and must be SILENT,
// while one that cannot be read is a FAILURE the caller can surface. Folding
// the two together is how a tenant whose disabled rules failed to load ends up
// looking at the full shipped catalog with no indication anything went wrong.
func TestFileStoreDistinguishesMissingFromBroken(t *testing.T) {
	fresh := NewFileStore(filepath.Join(t.TempDir(), "never-written.json"))
	if err := fresh.LoadErr(); err != nil {
		t.Fatalf("a never-written state file must not be reported as a failure: %v", err)
	}

	// A file that exists but is not the expected JSON IS a failure.
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte("{this is not json"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	bs := NewFileStore(broken)
	if bs.LoadErr() == nil {
		t.Fatal("a corrupt state file was silently treated as an empty store")
	}
	// …and it still SERVES: refusing to boot over a preferences file would be
	// worse than serving the shipped defaults, as long as the fact is reported.
	states, err := bs.RuleStates(context.Background(), "acme", false)
	if err != nil || len(states) != 0 {
		t.Fatalf("a store that failed to load must still serve empty state: %v %v", states, err)
	}

	// An unreadable file is likewise a failure, not an empty store.
	unreadable := filepath.Join(dir, "unreadable.json")
	if err := os.WriteFile(unreadable, []byte(`{"rules":[],"views":[]}`), 0o000); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 0000 is still readable, so the unreadable case cannot be exercised")
	}
	if us := NewFileStore(unreadable); us.LoadErr() == nil {
		t.Fatal("an unreadable state file was silently treated as an empty store")
	}
}
