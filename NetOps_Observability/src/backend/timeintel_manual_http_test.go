// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// timeintel_manual_http_test.go — the embedded-investigation close/verification
// surface (#7): GET/POST /api/correlations/{id}/time-events through the REAL
// router + auth middleware. Asserts (CLAUDE.md §3a.5):
//   - own-only list: a tenant's manual close is invisible to another tenant
//   - cross-tenant DELETE of another tenant's event → 404
//   - the actor is stamped from the TOKEN (created_by), never the body
//   - close verification is allowlisted; an override is server-labeled, never
//     silent; verification on a non-close event is rejected.

import (
	"encoding/json"
	"net/http/httptest"
	"netops/backend/timeintel"
	"strings"
	"testing"
	"time"
)

type timeEventWire struct {
	ID        string `json:"id"`
	EventType string `json:"event_type"`
	Note      string `json:"note"`
	CreatedBy string `json:"created_by"`
}

func setupTimeEventOrgs(t *testing.T) (srv *httptest.Server, tokens map[string]string) {
	t.Helper()
	hs, s := newTestServerState(t)
	s.incidentTimeline = timeintel.NewMemTimelineStore()

	admin := login(t, hs, "admin", "Passw0rd!2345").Token
	tokens = map[string]string{"admin": admin}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, hs, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		st, b = do(t, hs, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": idOf(t, b)})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		user := "tev-user-" + name
		st, b2 := do(t, hs, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": idOf(t, b),
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b2)
		}
		tokens[name] = login(t, hs, user, "Passw0rd!2345").Token
	}
	return hs, tokens
}

func TestTimeEventsCloseIsolationAndVerification(t *testing.T) {
	srv, tok := setupTimeEventOrgs(t)
	const corr = "33333333-3333-3333-3333-333333333333"
	path := "/api/correlations/" + corr + "/time-events"
	now := time.Now().UTC().Format(time.RFC3339)

	// A closes the investigation with an explicit override.
	st, b := do(t, srv, "POST", path, tok["A"], map[string]any{
		"event_type": "closed", "event_time": now,
		"verification": "override_signal_present", "note": "paging storm, closing by hand",
	})
	if st != 200 {
		t.Fatalf("A close: %d %s", st, b)
	}
	var created timeEventWire
	if err := json.Unmarshal(b, &created); err != nil || created.ID == "" {
		t.Fatalf("close response: %s", b)
	}
	// 1) actor stamped from the token, never the body.
	if created.CreatedBy != "tev-user-A" {
		t.Fatalf("created_by = %q, want tev-user-A", created.CreatedBy)
	}
	// 2) the override is server-labeled in the stored note — never silent.
	if !strings.HasPrefix(created.Note, "Override — closed while the signal was still present") {
		t.Fatalf("override not labeled: note=%q", created.Note)
	}
	if !strings.Contains(created.Note, "paging storm") {
		t.Fatalf("operator note dropped: %q", created.Note)
	}

	// 3) own-only list: A sees its event, B sees NONE on the same correlation.
	st, b = do(t, srv, "GET", path, tok["A"], nil)
	if st != 200 {
		t.Fatalf("A list: %d %s", st, b)
	}
	var lst struct {
		Events []timeEventWire `json:"events"`
	}
	if err := json.Unmarshal(b, &lst); err != nil || len(lst.Events) != 1 {
		t.Fatalf("A should see exactly its own event: %s", b)
	}
	st, b = do(t, srv, "GET", path, tok["B"], nil)
	if st != 200 {
		t.Fatalf("B list: %d %s", st, b)
	}
	if err := json.Unmarshal(b, &lst); err != nil || len(lst.Events) != 0 {
		t.Fatalf("cross-tenant leak — B sees A's events: %s", b)
	}

	// 4) cross-tenant delete → 404 (never reveal another tenant's row).
	st, _ = do(t, srv, "DELETE", path+"/"+created.ID, tok["B"], nil)
	if st != 404 {
		t.Fatalf("B deleting A's event = %d, want 404", st)
	}
	// A's event survives.
	st, b = do(t, srv, "GET", path, tok["A"], nil)
	if st != 200 {
		t.Fatalf("A relist: %d", st)
	}
	if err := json.Unmarshal(b, &lst); err != nil || len(lst.Events) != 1 {
		t.Fatalf("A's event was lost after B's cross-tenant delete attempt: %s", b)
	}

	// 5) verification is allowlisted, and only valid on close events.
	st, _ = do(t, srv, "POST", path, tok["A"], map[string]any{
		"event_type": "closed", "event_time": now, "verification": "totally_fine_trust_me",
	})
	if st != 400 {
		t.Fatalf("unknown verification accepted: %d", st)
	}
	st, _ = do(t, srv, "POST", path, tok["A"], map[string]any{
		"event_type": "acknowledged", "event_time": now, "verification": "verified_clear",
	})
	if st != 400 {
		t.Fatalf("verification on non-close event accepted: %d", st)
	}

	// 6) a verified-clear close records the verified label.
	st, b = do(t, srv, "POST", path, tok["B"], map[string]any{
		"event_type": "closed", "event_time": now, "verification": "verified_clear",
	})
	if st != 200 {
		t.Fatalf("B verified close: %d %s", st, b)
	}
	if err := json.Unmarshal(b, &created); err != nil ||
		!strings.HasPrefix(created.Note, "Verified clear") {
		t.Fatalf("verified close not labeled: %s", b)
	}
}
