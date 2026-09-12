// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// incident_id_test.go — a derived incident has no stored id, so its id is
// recomputed from the live clock on every request. These tests run the routes
// against a clock that MOVES, because every other fixture in this package
// freezes time and a frozen clock cannot see an id that only survives one
// second.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// stepClock advances a fixed step on every read, the way a real clock advances
// between the list request and the request an operator makes from what the list
// showed them.
type stepClock struct {
	mu   sync.Mutex
	at   time.Time
	step time.Duration
}

func newStepClock(start time.Time, step time.Duration) *stepClock {
	return &stepClock{at: start, step: step}
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.at
	c.at = c.at.Add(c.step)
	return now
}

// TestIncidentIDIsStableWithinTheWindowHour pins the identity rule itself: two
// window starts in the same hour are the same incident, and the next hour is a
// different one. Hashing the raw instant made every second a new incident.
func TestIncidentIDIsStableWithinTheWindowHour(t *testing.T) {
	base := time.Date(2026, 9, 5, 11, 0, 0, 0, time.UTC)
	first := IncidentID("acme", "journey", "checkout", base)
	for _, offset := range []time.Duration{
		time.Millisecond, time.Second, 30 * time.Second, 59*time.Minute + 59*time.Second,
	} {
		if got := IncidentID("acme", "journey", "checkout", base.Add(offset)); got != first {
			t.Fatalf("a window start %s later produced id %q, want %q — an id that changes "+
				"as the clock ticks makes every shared link dead on arrival", offset, got, first)
		}
	}
	if got := IncidentID("acme", "journey", "checkout", base.Add(time.Hour)); got == first {
		t.Fatal("the next hour produced the SAME id: the id must still separate one window from the next")
	}
	// A non-UTC clock must land in the same bucket, or the same moment would be
	// two incidents depending on where the caller's clock is set.
	east, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("no tzdata in this environment: %v", err)
	}
	if got := IncidentID("acme", "journey", "checkout", base.In(east)); got != first {
		t.Fatalf("the same instant in another zone produced %q, want %q", got, first)
	}
}

// TestDerivedIncidentIDResolvesAfterTheClockAdvances is the regression: take an
// id off the list route, then ask the item routes for it a moment later, the
// way an operator clicking a row or opening a shared link does. Before the
// window start was quantised, a step of one second was enough to turn every one
// of these into a 404.
func TestDerivedIncidentIDResolvesAfterTheClockAdvances(t *testing.T) {
	for _, step := range []time.Duration{100 * time.Millisecond, time.Second, 5 * time.Second} {
		t.Run(step.String(), func(t *testing.T) {
			clock := newStepClock(testNow, step)
			api, _ := promoteAPIAt(t, newFakePromoter(), NewFileStore(""), "acme", clock.Now)

			id := derivedIncidentID(t, api, "acme")
			// The list itself must not disagree with itself either.
			if again := derivedIncidentID(t, api, "acme"); again != id {
				t.Fatalf("two list calls %s apart named the same incident %q and %q", step, id, again)
			}
			for _, sub := range []string{"", "/evidence", "/timeline", "/path"} {
				code, body := call(t, api.HandleIncidentItem, http.MethodGet,
					IncidentItemPath+id+sub, "", nil)
				if code != http.StatusOK {
					t.Fatalf("GET %s%s answered %d after the clock moved by %s: %s",
						IncidentItemPath+id, sub, code, step, body)
				}
			}
		})
	}
}

// TestPromotionSurvivesTheClockAdvancing covers the write. A promotion is
// stored under the derived id, so an id that moves both refuses the promote
// call and, once one has landed, drops the "promoted" stamp off the next read.
func TestPromotionSurvivesTheClockAdvancing(t *testing.T) {
	clock := newStepClock(testNow, time.Second)
	store := NewFileStore("")
	api, _ := promoteAPIAt(t, newFakePromoter(), store, "acme", clock.Now)

	id := derivedIncidentID(t, api, "acme")
	code, body := call(t, api.HandleIncidentItem, http.MethodPost, IncidentItemPath+id+"/promote", "", nil)
	if code != http.StatusCreated {
		t.Fatalf("promoting the id the list just handed out answered %d, want 201: %s", code, body)
	}
	var promoted PromoteResponse
	if err := json.Unmarshal(body, &promoted); err != nil {
		t.Fatalf("decode promote response: %v (%s)", err, body)
	}
	if promoted.IncidentID == "" {
		t.Fatalf("the promotion carried no platform incident id: %s", body)
	}
	if _, err := store.GetPromotion(context.Background(), "acme", id); err != nil {
		t.Fatalf("the promotion was not stored under the derived id %q: %v", id, err)
	}

	// Seconds later the SAME incident must still be listed as promoted:
	// ApplyPromotions keys on the derived id, so an id that moves silently
	// un-promotes an incident a human already acted on.
	listCode, listBody := callTenant(t, api.HandleIncidents, http.MethodGet, IncidentsPath, "", "acme")
	if listCode != http.StatusOK {
		t.Fatalf("list: %d %s", listCode, listBody)
	}
	var list IncidentsResponse
	if err := json.Unmarshal(listBody, &list); err != nil {
		t.Fatalf("decode list: %v (%s)", err, listBody)
	}
	var seen bool
	for _, row := range list.Incidents {
		if row.ID != id {
			continue
		}
		seen = true
		if !row.Promoted || row.IncidentID != promoted.IncidentID {
			t.Fatalf("the promoted incident lost its stamp on the next read: %+v", row)
		}
	}
	if !seen {
		t.Fatalf("the promoted id %q vanished from the list once the clock moved: %s", id, listBody)
	}

	// Promoting again folds into the same platform incident rather than raising
	// a second one, which only holds while the derived id holds.
	code, body = call(t, api.HandleIncidentItem, http.MethodPost, IncidentItemPath+id+"/promote", "", nil)
	if code != http.StatusOK {
		t.Fatalf("a second promote answered %d, want 200 (already promoted): %s", code, body)
	}
	if !strings.Contains(string(body), promoted.IncidentID) {
		t.Fatalf("the second promote did not return the first incident id: %s", body)
	}
}
