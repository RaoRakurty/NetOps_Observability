// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"testing"
	"time"
)

func TestMemAIFeedbackStoreIsolationAndAgg(t *testing.T) {
	m := &memFeedbackStore{by: map[string]FeedbackRow{}}
	ctx := context.Background()
	now := time.Now().UTC()
	put := func(tenant, id, intent, rating string) {
		_ = m.Put(ctx, FeedbackRow{TenantID: tenant, ID: id, Intent: intent, Rating: rating, At: now})
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
	_ = m.Put(ctx, FeedbackRow{TenantID: "acme", ID: "old", Intent: "x", Rating: "down", At: now.Add(-2 * time.Hour)})
	if recent, _ := m.Stats(ctx, "acme", false, 3600); recent.Down != 1 {
		t.Errorf("2h-old feedback should be outside a 1h window, got down=%d", recent.Down)
	}
}

// TestNewMemFeedbackStorePutDoesNotPanic pins the CONSTRUCTOR, not a hand-built
// struct literal. The shipped bug was that NewMemFeedbackStore returned a store
// with a nil map, so the first Put panicked ("assignment to entry in nil map")
// and every POST /api/ai/feedback tore down its connection. The pre-existing
// isolation test built `&memFeedbackStore{by: ...}` directly and therefore could
// never have caught it — this one exercises the exported path the server uses.
func TestNewMemFeedbackStorePutDoesNotPanic(t *testing.T) {
	m := NewMemFeedbackStore()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := m.Put(ctx, FeedbackRow{TenantID: "acme", ID: "1", Intent: "capability", Rating: "up", At: now}); err != nil {
		t.Fatalf("Put on a freshly constructed store: %v", err)
	}
	st, err := m.Stats(ctx, "acme", false, 3600)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Up != 1 || st.Down != 0 {
		t.Fatalf("up/down = %d/%d, want 1/0", st.Up, st.Down)
	}
}

// TestZeroValueMemFeedbackStorePutDoesNotPanic covers the same trap reached
// through the zero value rather than the constructor.
func TestZeroValueMemFeedbackStorePutDoesNotPanic(t *testing.T) {
	var m memFeedbackStore
	if err := m.Put(context.Background(), FeedbackRow{TenantID: "acme", ID: "1", Rating: "down", At: time.Now().UTC()}); err != nil {
		t.Fatalf("Put on a zero-value store: %v", err)
	}
}
