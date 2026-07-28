package main

import (
	"context"
	"netops/backend/internal/incident"
	"os"
	"testing"
)

// incidents_display_test.go — #103 UX for the Incident system: the human
// INC-XXXXXX handle and the notified-via delivery record.

func TestIncidentDisplayID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"8591a323df59f393", "INC-8591A3"}, // the owner's raw-hex complaint
		{"INC-8591A3", "INC-8591A3"},       // idempotent
		{"", ""},                           // safe on empty
		{"ab12", "ab12"},                   // too short → unchanged
		{"deadbeefcafef00d", "INC-DEADBE"}, // randHex(8) shape
	}
	for _, c := range cases {
		if got := incident.DisplayID(c.in); got != c.want {
			t.Errorf("incident.DisplayID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestIncidentNotifiedVia_PG pins the delivery record: MarkNotified appends a
// `notified` timeline event and List/Get derive notified_via from it (distinct,
// delivery-only — nothing recorded means nothing shown). Gated like the other
// live-PG incident tests.
func TestIncidentNotifiedVia_PG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres incident test")
	}
	ctx := context.Background()
	ps, err := newPgStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.db.close()
	store := incident.NewPGStore(rlsPG{db: ps.db})

	inc, _, err := store.Ingest(ctx, IncidentInput{
		TenantID: "acme", Title: "Link flap on edge-2", Severity: "critical",
		SourceType: "alert", SourceID: "rule-flap", DedupKey: "flap:edge-2", Actor: "engine",
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(inc.NotifiedVia) != 0 {
		t.Fatalf("fresh incident must have no recorded deliveries, got %v", inc.NotifiedVia)
	}

	// Two deliveries to the same channel collapse; a second channel adds.
	for _, ch := range []string{"slack", "slack", "email"} {
		if err := store.MarkNotified(ctx, inc.ID, ch); err != nil {
			t.Fatalf("mark notified %s: %v", ch, err)
		}
	}
	got, _, found, err := store.Get(ctx, "acme", false, inc.ID)
	if err != nil || !found {
		t.Fatalf("get: err=%v found=%v", err, found)
	}
	if len(got.NotifiedVia) != 2 {
		t.Fatalf("notified_via = %v, want [email slack] (distinct)", got.NotifiedVia)
	}
	seen := map[string]bool{}
	for _, ch := range got.NotifiedVia {
		seen[ch] = true
	}
	if !seen["slack"] || !seen["email"] {
		t.Fatalf("notified_via = %v, want slack + email", got.NotifiedVia)
	}

	// The list read carries it too (the UI column reads the list).
	list, err := store.List(ctx, "acme", false, IncidentQuery{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, li := range list {
		if li.ID == inc.ID && len(li.NotifiedVia) != 2 {
			t.Fatalf("list notified_via = %v, want 2 channels", li.NotifiedVia)
		}
	}
}
