package main

import (
	"context"
	"testing"
	"time"
)

func TestMemAIFeedbackStoreIsolationAndAgg(t *testing.T) {
	m := &memAIFeedbackStore{by: map[string]aiFeedbackRow{}}
	ctx := context.Background()
	now := time.Now().UTC()
	put := func(tenant, id, intent, rating string) {
		_ = m.Put(ctx, aiFeedbackRow{TenantID: tenant, ID: id, Intent: intent, Rating: rating, At: now})
	}
	put("acme", "1", "problem_explanation", "up")
	put("acme", "2", "problem_explanation", "down")
	put("acme", "3", "current_state", "up")
	put("globex", "4", "problem_explanation", "down")

	// Default-closed: acme sees only its own (2 up, 1 down).
	acme, _ := m.Stats(ctx, "acme", false, 3600)
	if acme.Up != 2 || acme.Down != 1 {
		t.Fatalf("acme up/down = %d/%d, want 2/1", acme.Up, acme.Down)
	}
	if c := acme.ByIntent["problem_explanation"]; c == nil || c.Up != 1 || c.Down != 1 {
		t.Errorf("acme problem_explanation breakdown wrong: %+v", c)
	}
	// globex isolated.
	glob, _ := m.Stats(ctx, "globex", false, 3600)
	if glob.Up != 0 || glob.Down != 1 {
		t.Fatalf("globex up/down = %d/%d, want 0/1", glob.Up, glob.Down)
	}
	// Cross-tenant sees all.
	all, _ := m.Stats(ctx, "", true, 3600)
	if all.Up+all.Down != 4 {
		t.Fatalf("cross view should count all 4, got %d", all.Up+all.Down)
	}
	// Window excludes old feedback.
	_ = m.Put(ctx, aiFeedbackRow{TenantID: "acme", ID: "old", Intent: "x", Rating: "down", At: now.Add(-2 * time.Hour)})
	if recent, _ := m.Stats(ctx, "acme", false, 3600); recent.Down != 1 {
		t.Errorf("2h-old feedback should be outside a 1h window, got down=%d", recent.Down)
	}
}
