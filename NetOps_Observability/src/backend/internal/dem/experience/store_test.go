package experience

// store_test.go — the store half of §3a rule 4: isolation lives in the STORE,
// so a lookup for tenant A can only ever walk A's bucket. The HTTP half is
// src/backend/dem_experience_isolation_test.go.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
