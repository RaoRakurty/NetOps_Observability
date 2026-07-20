package main

// alert_episodes_test.go — episode fold/close/reopen matrix, flap detection,
// notification suppression, triage HTTP surface + audit trail. The cross-org
// isolation guard lives in alert_episodes_isolation_test.go.

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/models"
)

// newEpisodeStore builds a store with a controllable clock and no env noise.
func newEpisodeStore(t *testing.T) (*alertEpisodeStore, *fakeEpisodeClock) {
	t.Helper()
	clock := &fakeEpisodeClock{t: time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)}
	s := newAlertEpisodeStore(filepath.Join(t.TempDir(), "episodes.json"))
	s.closeWindow = 15 * time.Minute
	s.flapFlips = 4
	s.flapWindow = 10 * time.Minute
	s.now = clock.now
	return s, clock
}

type fakeEpisodeClock struct{ t time.Time }

func (c *fakeEpisodeClock) now() time.Time          { return c.t }
func (c *fakeEpisodeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func listAll(t *testing.T, s *alertEpisodeStore) []AlertEpisode {
	t.Helper()
	eps, _, _ := s.List("", true, episodeQuery{Status: "all"})
	return eps
}

func TestEpisodeFoldCloseReopenMatrix(t *testing.T) {
	s, clock := newEpisodeStore(t)

	// 1. First firing → one active episode, count 1.
	s.Observe("acme", "leaf1", "HighCPU", "critical", "CPU 95%", true)
	eps := listAll(t, s)
	if len(eps) != 1 || eps[0].Status != episodeStatusActive || eps[0].Count != 1 {
		t.Fatalf("first firing: want 1 active episode count=1, got %+v", eps)
	}
	first := eps[0]

	// 2. Clear, then re-fire INSIDE the close window → folds into the SAME
	// episode: count 2, first_seen preserved, last_seen advanced.
	clock.advance(2 * time.Minute)
	s.Observe("acme", "leaf1", "HighCPU", "critical", "", false)
	clock.advance(5 * time.Minute) // still < closeWindow after the clear
	s.Observe("acme", "leaf1", "HighCPU", "critical", "CPU 97%", true)
	eps = listAll(t, s)
	if len(eps) != 1 {
		t.Fatalf("re-fire inside window must fold, got %d episodes", len(eps))
	}
	if eps[0].ID != first.ID || eps[0].Count != 2 || !eps[0].FirstSeen.Equal(first.FirstSeen) {
		t.Fatalf("fold broken: %+v (want id=%s count=2 first_seen preserved)", eps[0], first.ID)
	}
	if eps[0].Summary != "CPU 97%" {
		t.Fatalf("summary must track the latest firing, got %q", eps[0].Summary)
	}

	// 3. A different state (severity) is a DIFFERENT episode.
	s.Observe("acme", "leaf1", "HighCPU", "warning", "CPU 82%", true)
	if eps = listAll(t, s); len(eps) != 2 {
		t.Fatalf("distinct (resource,signal,state) must not fold together: %d episodes", len(eps))
	}

	// 4. Clear + quiet gap beyond the close window → episode closes.
	clock.advance(time.Minute)
	s.Observe("acme", "leaf1", "HighCPU", "critical", "", false)
	clock.advance(16 * time.Minute)                             // > closeWindow
	s.Observe("acme", "leaf1", "HighCPU", "warning", "", false) // any observe sweeps
	var crit AlertEpisode
	for _, ep := range listAll(t, s) {
		if ep.State == "critical" {
			crit = ep
		}
	}
	if crit.Status != episodeStatusClosed {
		t.Fatalf("cleared episode past the quiet window must close, got %q", crit.Status)
	}

	// 5. Re-fire AFTER close → a brand-new episode (count restarts).
	s.Observe("acme", "leaf1", "HighCPU", "critical", "CPU 99%", true)
	fresh := 0
	for _, ep := range listAll(t, s) {
		if ep.State == "critical" && ep.Status == episodeStatusActive {
			fresh++
			if ep.ID == first.ID || ep.Count != 1 {
				t.Fatalf("re-fire after close must start a NEW episode: %+v", ep)
			}
		}
	}
	if fresh != 1 {
		t.Fatalf("want exactly one fresh active critical episode, got %d", fresh)
	}
}

func TestEpisodeStillFiringNeverCloses(t *testing.T) {
	s, clock := newEpisodeStore(t)
	s.Observe("acme", "leaf1", "HighCPU", "critical", "CPU 95%", true)
	clock.advance(10 * s.closeWindow) // continuously firing — no clear ever observed
	eps, _, _ := s.List("", true, episodeQuery{})
	if len(eps) != 1 || eps[0].Status != episodeStatusActive {
		t.Fatalf("an actively-firing episode must never age out, got %+v", eps)
	}
}

func TestEpisodeFlapDetection(t *testing.T) {
	s, clock := newEpisodeStore(t) // 4 flips inside 10m marks flapping

	// 3 flips (fire, clear, fire, clear = 3 transitions after the first fire)
	// inside the window: NOT yet flapping.
	s.Observe("acme", "leaf1", "LinkFlap", "warning", "if down", true)
	for i := 0; i < 1; i++ {
		clock.advance(time.Minute)
		s.Observe("acme", "leaf1", "LinkFlap", "warning", "", false)
		clock.advance(time.Minute)
		s.Observe("acme", "leaf1", "LinkFlap", "warning", "if down", true)
	}
	clock.advance(time.Minute)
	s.Observe("acme", "leaf1", "LinkFlap", "warning", "", false)
	eps := listAll(t, s)
	if eps[0].Flapping {
		t.Fatalf("3 flips must not mark flapping yet: %+v", eps[0])
	}

	// One more fire→clear cycle crosses the threshold (5 flips in window).
	clock.advance(time.Minute)
	s.Observe("acme", "leaf1", "LinkFlap", "warning", "if down", true)
	eps = listAll(t, s)
	if !eps[0].Flapping {
		t.Fatalf("4+ flips inside the window must mark flapping: flips=%d %+v", eps[0].FlipCount, eps[0])
	}
	// Flapping is VISIBLE state, never suppression: the episode stays listed
	// and its notifications are untouched (no mute was applied).
	if s.Suppressed("acme", "leaf1", "LinkFlap", "warning") {
		t.Fatal("flapping must never silently suppress notifications")
	}
}

func TestEpisodeFlapWindowExcludesOldFlips(t *testing.T) {
	s, clock := newEpisodeStore(t)
	s.Observe("acme", "leaf1", "LinkFlap", "warning", "", true)
	// 3 slow flips spread WIDER than the flap window (but each re-fire inside
	// the close window, so it keeps folding), then one more — never >= 4 flips
	// within any 10m window.
	for i := 0; i < 4; i++ {
		clock.advance(6 * time.Minute)
		s.Observe("acme", "leaf1", "LinkFlap", "warning", "", false)
		clock.advance(6 * time.Minute)
		s.Observe("acme", "leaf1", "LinkFlap", "warning", "", true)
	}
	eps := listAll(t, s)
	if len(eps) != 1 || eps[0].Flapping {
		t.Fatalf("slow flips outside the window must not mark flapping: %+v", eps)
	}
}

func TestEpisodeSuppressionRules(t *testing.T) {
	s, clock := newEpisodeStore(t)
	s.Observe("acme", "leaf1", "HighCPU", "critical", "CPU 95%", true)
	ep := listAll(t, s)[0]

	if s.Suppressed("acme", "leaf1", "HighCPU", "critical") {
		t.Fatal("a fresh episode must not be suppressed")
	}
	// Mute → suppressed.
	if _, err := s.Triage(ep.ID, "acme", false, func(e *AlertEpisode) error { e.Muted, e.MutedBy = true, "op"; return nil }); err != nil {
		t.Fatal(err)
	}
	if !s.Suppressed("acme", "leaf1", "HighCPU", "critical") {
		t.Fatal("muted episode must suppress notifications")
	}
	// Unmute + snooze into the future → suppressed until it lapses.
	until := clock.now().Add(30 * time.Minute)
	if _, err := s.Triage(ep.ID, "acme", false, func(e *AlertEpisode) error {
		e.Muted, e.MutedBy = false, ""
		e.SnoozedUntil, e.SnoozedBy = &until, "op"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !s.Suppressed("acme", "leaf1", "HighCPU", "critical") {
		t.Fatal("snoozed episode must suppress notifications")
	}
	clock.advance(31 * time.Minute)
	if s.Suppressed("acme", "leaf1", "HighCPU", "critical") {
		t.Fatal("a lapsed snooze must resume notifications automatically")
	}

	// Close the episode; a NEW episode never inherits the old mute/snooze.
	s.Observe("acme", "leaf1", "HighCPU", "critical", "", false)
	clock.advance(16 * time.Minute)
	s.Observe("acme", "leaf1", "HighCPU", "critical", "CPU 99%", true) // new episode
	if s.Suppressed("acme", "leaf1", "HighCPU", "critical") {
		t.Fatal("a new episode must start with notifications on")
	}
}

func TestEpisodePersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "episodes.json")
	clock := &fakeEpisodeClock{t: time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)}
	s := newAlertEpisodeStore(path)
	s.now = clock.now
	s.Observe("acme", "leaf1", "HighCPU", "critical", "CPU 95%", true)
	ep := listAll(t, s)[0]
	if _, err := s.Triage(ep.ID, "acme", false, func(e *AlertEpisode) error {
		e.Notes = append(e.Notes, EpisodeNote{At: clock.now(), By: "op", Text: "checking"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	s2 := newAlertEpisodeStore(path) // reload from disk
	s2.now = clock.now
	eps := listAll(t, s2)
	if len(eps) != 1 || eps[0].ID != ep.ID || len(eps[0].Notes) != 1 {
		t.Fatalf("episodes must survive a restart with triage state: %+v", eps)
	}
	// The reloaded episode is still OPEN — a re-fire folds rather than forking.
	s2.Observe("acme", "leaf1", "HighCPU", "critical", "", false)
	s2.Observe("acme", "leaf1", "HighCPU", "critical", "CPU 96%", true)
	if eps = listAll(t, s2); len(eps) != 1 || eps[0].Count != 2 {
		t.Fatalf("reloaded episode must keep folding: %+v", eps)
	}
}

func TestEpisodeListBoundsAndDisclosure(t *testing.T) {
	s, _ := newEpisodeStore(t)
	for i := 0; i < 25; i++ {
		s.Observe("acme", fmt.Sprintf("dev-%02d", i), "HighCPU", "critical", "x", true)
	}
	eps, total, truncated := s.List("", true, episodeQuery{Limit: 10})
	if len(eps) != 10 || total != 25 || !truncated {
		t.Fatalf("bounded list must disclose truncation: len=%d total=%d truncated=%v", len(eps), total, truncated)
	}
	eps, total, truncated = s.List("", true, episodeQuery{})
	if len(eps) != 25 || total != 25 || truncated {
		t.Fatalf("default limit covers 25 rows: len=%d total=%d truncated=%v", len(eps), total, truncated)
	}
}

func TestEpisodeRetentionNeverEvictsFiring(t *testing.T) {
	s, clock := newEpisodeStore(t)
	// Overflow the per-tenant cap with CLOSED episodes plus one active one.
	s.Observe("acme", "keeper", "HighCPU", "critical", "", true)
	for i := 0; i < episodeMaxPerTenant+10; i++ {
		res := fmt.Sprintf("dev-%04d", i)
		s.Observe("acme", res, "HighCPU", "critical", "", true)
		s.Observe("acme", res, "HighCPU", "critical", "", false)
		clock.advance(time.Second)
	}
	clock.advance(16 * time.Minute)
	s.Observe("acme", "sweep-trigger", "Other", "warning", "", true)
	found := false
	active, _, _ := s.List("", true, episodeQuery{Status: episodeStatusActive, Limit: episodeMaxQueryLimit})
	for _, ep := range active {
		if ep.Resource == "keeper" {
			found = true
		}
	}
	if !found {
		t.Fatal("retention eviction must never drop an actively-firing episode")
	}
	eps, total, _ := s.List("acme", false, episodeQuery{Status: "all", Limit: episodeMaxQueryLimit})
	_ = eps
	if total > episodeMaxPerTenant+1 { // +1 slack for the just-inserted trigger row
		t.Fatalf("per-tenant retention cap not enforced: %d episodes", total)
	}
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
	events := s.audit.List("", true, auditQuery{Limit: 100})
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
