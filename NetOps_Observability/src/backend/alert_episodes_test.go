// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// alert_episodes_test.go — the engine→server adapters and the HTTP triage
// surface + audit trail. The pure store suite moved to alerts/episodes_test.go
// with the store (Phase-2 W1.3); the fixtures below are duplicated (test files
// cannot cross packages).

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/models"
)

// newEpisodeStore builds a store with a controllable clock and no env noise.
func newEpisodeStore(t *testing.T) (*alertEpisodeStore, *fakeEpisodeClock) {
	t.Helper()
	clock := &fakeEpisodeClock{t: time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)}
	s := alerts.NewEpisodeStore(filepath.Join(t.TempDir(), "episodes.json"), 15*time.Minute, 4, 10*time.Minute)
	s.SetNowForTest(clock.now)
	return s, clock
}

type fakeEpisodeClock struct{ t time.Time }

func (c *fakeEpisodeClock) now() time.Time { return c.t }

func listAll(t *testing.T, s *alertEpisodeStore) []AlertEpisode {
	t.Helper()
	eps, _, _ := s.List("", true, episodeQuery{Status: "all"})
	return eps
}

// ── engine → server adapter ───────────────────────────────────────────────────

func TestObserveAlertTransitionDerivesTenantFromDevice(t *testing.T) {
	_, s := newTestServerState(t)
	store, _ := newEpisodeStore(t)
	s.alertEpisodes = store
	s.discovery.Upsert(models.Device{ID: "leaf1", Name: "leaf1", TenantID: "acme"})

	s.observeAlertTransition(models.Alert{ID: "HighCPU|device=leaf1", Rule: "HighCPU", Severity: "Critical", DeviceID: "leaf1", Summary: "CPU 95%"}, true)
	s.observeAlertTransition(models.Alert{ID: "StackDisk", Rule: "StackDisk", Severity: "warning", Summary: "disk 90%"}, true)

	eps := listAll(t, store)
	if len(eps) != 2 {
		t.Fatalf("want 2 episodes, got %d", len(eps))
	}
	for _, ep := range eps {
		switch ep.Signal {
		case "HighCPU":
			if ep.TenantID != "acme" || ep.State != "critical" {
				t.Fatalf("tenant must come from the DEVICE, state normalized: %+v", ep)
			}
		case "StackDisk":
			if ep.TenantID != "" {
				t.Fatalf("device-less alerts are platform-owned: %+v", ep)
			}
		}
	}
	// Suppression adapter resolves the same key.
	ep := eps[0]
	if _, err := store.Triage(ep.ID, "", true, func(e *AlertEpisode) error { e.Muted = true; return nil }); err != nil {
		t.Fatal(err)
	}
	a := models.Alert{Rule: ep.Signal, Severity: ep.State, DeviceID: ep.Resource}
	if !s.alertNotifySuppressed(a) {
		t.Fatalf("adapter must suppress the muted episode's alert: %+v", ep)
	}
}

// ── HTTP triage surface + audit trail ─────────────────────────────────────────

func TestEpisodeTriageHTTPAndAudit(t *testing.T) {
	srv, s := newTestServerState(t)
	store, clock := newEpisodeStore(t)
	s.alertEpisodes = store
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	store.Observe("", "", "StackDisk", "warning", "disk 90%", true)
	ep := listAll(t, store)[0]
	base := "/api/alerts/episodes/" + ep.ID

	// ack
	st, b := do(t, srv, "POST", base+"/ack", admin, map[string]any{"acknowledged": true})
	if st != 200 {
		t.Fatalf("ack: %d %s", st, b)
	}
	var got AlertEpisode
	if err := json.Unmarshal(b, &got); err != nil || got.AcknowledgedBy != "admin" || got.AcknowledgedAt == nil {
		t.Fatalf("ack must stamp the PRINCIPAL as actor: %s", b)
	}
	// assign — payload actor fields must be impossible (only assignee accepted).
	if st, b = do(t, srv, "POST", base+"/assign", admin, map[string]any{"assignee": "noc-lee"}); st != 200 {
		t.Fatalf("assign: %d %s", st, b)
	}
	if st, b = do(t, srv, "POST", base+"/assign", admin, map[string]any{"assignee": "bad name!"}); st != 400 {
		t.Fatalf("assign must reject a malformed assignee: %d %s", st, b)
	}
	// mute / snooze
	if st, b = do(t, srv, "POST", base+"/mute", admin, map[string]any{"muted": true}); st != 200 {
		t.Fatalf("mute: %d %s", st, b)
	}
	if !store.Suppressed("", "", "StackDisk", "warning") {
		t.Fatal("mute over HTTP must suppress notifications")
	}
	until := clock.now().Add(2 * time.Hour).Format(time.RFC3339)
	if st, b = do(t, srv, "POST", base+"/snooze", admin, map[string]any{"until": until}); st != 200 {
		t.Fatalf("snooze: %d %s", st, b)
	}
	if st, _ = do(t, srv, "POST", base+"/snooze", admin, map[string]any{"until": clock.now().Add(-time.Hour).Format(time.RFC3339)}); st != 400 {
		t.Fatalf("snooze in the past must be rejected: %d", st)
	}
	if st, _ = do(t, srv, "POST", base+"/snooze", admin, map[string]any{"until": clock.now().Add(30 * 24 * time.Hour).Format(time.RFC3339)}); st != 400 {
		t.Fatalf("snooze beyond the cap must be rejected: %d", st)
	}
	// notes
	if st, b = do(t, srv, "POST", base+"/notes", admin, map[string]any{"text": "correlated with maintenance"}); st != 200 {
		t.Fatalf("notes: %d %s", st, b)
	}
	if st, _ = do(t, srv, "POST", base+"/notes", admin, map[string]any{"text": ""}); st != 400 {
		t.Fatalf("empty note must be rejected: %d", st)
	}
	// unknown action / unknown id
	if st, _ = do(t, srv, "POST", base+"/explode", admin, map[string]any{}); st != 404 {
		t.Fatalf("unknown action must 404: %d", st)
	}
	if st, _ = do(t, srv, "POST", "/api/alerts/episodes/deadbeef/ack", admin, map[string]any{}); st != 404 {
		t.Fatalf("unknown id must 404: %d", st)
	}

	// Audit trail: every triage action recorded with who/what detail; note TEXT
	// itself must never appear in the trail.
	events := auditList(t, s, "", true, auditQuery{Limit: 100})
	actions := map[string]int{}
	for _, e := range events {
		if e.Method != "TRIAGE" {
			continue
		}
		if e.Actor != "admin" {
			t.Fatalf("triage audit must carry the actor: %+v", e)
		}
		if act, _ := e.Detail["action"].(string); act != "" {
			actions[act]++
		}
		if raw, _ := json.Marshal(e.Detail); strings.Contains(string(raw), "correlated with maintenance") {
			t.Fatalf("note text leaked into the audit trail: %s", raw)
		}
	}
	for _, want := range []string{"ack", "assign", "mute", "snooze", "notes"} {
		if actions[want] == 0 {
			t.Fatalf("missing audit event for %q (got %v)", want, actions)
		}
	}

	// The episode list surfaces the suppressed state honestly.
	st, b = do(t, srv, "GET", "/api/alerts/episodes", admin, nil)
	if st != 200 {
		t.Fatalf("list: %d %s", st, b)
	}
	var lr struct {
		Episodes []AlertEpisode `json:"episodes"`
		Total    int            `json:"total"`
	}
	if err := json.Unmarshal(b, &lr); err != nil || lr.Total != 1 || !lr.Episodes[0].Muted {
		t.Fatalf("muted episode must stay VISIBLE in the list: %s", b)
	}
}
