// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package alerts

// episodes_test.go — episode fold/close/reopen matrix, flap detection,
// notification suppression, persistence, bounds and retention (pure store
// suite, moved from package main). The HTTP triage surface + audit trail and
// the engine adapters are tested in package main.

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newEpisodeStore builds a store with a controllable clock and no env noise.
func newEpisodeStore(t *testing.T) (*EpisodeStore, *fakeEpisodeClock) {
	t.Helper()
	clock := &fakeEpisodeClock{t: time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)}
	s := NewEpisodeStore(filepath.Join(t.TempDir(), "episodes.json"), 15*time.Minute, 4, 10*time.Minute)
	s.SetNowForTest(clock.now)
	return s, clock
}

type fakeEpisodeClock struct{ t time.Time }

func (c *fakeEpisodeClock) now() time.Time          { return c.t }
func (c *fakeEpisodeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func listAll(t *testing.T, s *EpisodeStore) []Episode {
	t.Helper()
	eps, _, _ := s.List(EpisodeScopeFor("", true), EpisodeQuery{Status: "all"})
	return eps
}

func TestEpisodeFoldCloseReopenMatrix(t *testing.T) {
	s, clock := newEpisodeStore(t)

	// 1. First firing → one active episode, count 1.
	s.Observe("acme", "leaf1", "HighCPU", "critical", "CPU 95%", true)
	eps := listAll(t, s)
	if len(eps) != 1 || eps[0].Status != EpisodeStatusActive || eps[0].Count != 1 {
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
	var crit Episode
	for _, ep := range listAll(t, s) {
		if ep.State == "critical" {
			crit = ep
		}
	}
	if crit.Status != EpisodeStatusClosed {
		t.Fatalf("cleared episode past the quiet window must close, got %q", crit.Status)
	}

	// 5. Re-fire AFTER close → a brand-new episode (count restarts).
	s.Observe("acme", "leaf1", "HighCPU", "critical", "CPU 99%", true)
	fresh := 0
	for _, ep := range listAll(t, s) {
		if ep.State == "critical" && ep.Status == EpisodeStatusActive {
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
	clock.advance(10 * s.CloseWindow()) // continuously firing — no clear ever observed
	eps, _, _ := s.List(EpisodeScopeFor("", true), EpisodeQuery{})
	if len(eps) != 1 || eps[0].Status != EpisodeStatusActive {
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
	if _, err := s.Triage(ep.ID, EpisodeScopeFor("acme", false), func(e *Episode) error { e.Muted, e.MutedBy = true, "op"; return nil }); err != nil {
		t.Fatal(err)
	}
	if !s.Suppressed("acme", "leaf1", "HighCPU", "critical") {
		t.Fatal("muted episode must suppress notifications")
	}
	// Unmute + snooze into the future → suppressed until it lapses.
	until := clock.now().Add(30 * time.Minute)
	if _, err := s.Triage(ep.ID, EpisodeScopeFor("acme", false), func(e *Episode) error {
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
	s := NewEpisodeStore(path, 0, 0, 0)
	s.SetNowForTest(clock.now)
	s.Observe("acme", "leaf1", "HighCPU", "critical", "CPU 95%", true)
	ep := listAll(t, s)[0]
	if _, err := s.Triage(ep.ID, EpisodeScopeFor("acme", false), func(e *Episode) error {
		e.Notes = append(e.Notes, EpisodeNote{At: clock.now(), By: "op", Text: "checking"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	s2 := NewEpisodeStore(path, 0, 0, 0) // reload from disk
	s2.SetNowForTest(clock.now)
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
	eps, total, truncated := s.List(EpisodeScopeFor("", true), EpisodeQuery{Limit: 10})
	if len(eps) != 10 || total != 25 || !truncated {
		t.Fatalf("bounded list must disclose truncation: len=%d total=%d truncated=%v", len(eps), total, truncated)
	}
	eps, total, truncated = s.List(EpisodeScopeFor("", true), EpisodeQuery{})
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
	active, _, _ := s.List(EpisodeScopeFor("", true), EpisodeQuery{Status: EpisodeStatusActive, Limit: episodeMaxQueryLimit})
	for _, ep := range active {
		if ep.Resource == "keeper" {
			found = true
		}
	}
	if !found {
		t.Fatal("retention eviction must never drop an actively-firing episode")
	}
	eps, total, _ := s.List(EpisodeScopeFor("acme", false), EpisodeQuery{Status: "all", Limit: episodeMaxQueryLimit})
	_ = eps
	if total > episodeMaxPerTenant+1 { // +1 slack for the just-inserted trigger row
		t.Fatalf("per-tenant retention cap not enforced: %d episodes", total)
	}
}

// TestEpisodeListDeviceLessRowsAreGlobalOnlyWhenUnowned is the STORE half of the
// device-less alert isolation rule (review 2026-09-08, H10).
//
// The Digital Experience rules aggregate by target rather than device, so their
// episodes have an empty Resource but a real owning tenant, and their summary
// carries that tenant's target hostname, site and app. List used to
// short-circuit on `ep.Resource == ""` alone, which handed one tenant's targets
// to every other tenant.
//
// The rule is in the store because §3a rule 4 puts it there: every reader asks
// List, so a caller cannot forget it. Until this test the rule was covered only
// end-to-end through the HTTP surfaces — reverting `episodeVisible` to the old
// `ep.Resource == ""` left every test in this package green.
func TestEpisodeListDeviceLessRowsAreGlobalOnlyWhenUnowned(t *testing.T) {
	s, _ := newEpisodeStore(t)
	const target = "Experience target shop.acme.example (https) p95 is over budget"
	s.Observe("acme", "", "ExperienceLatencyOverBudget", "critical", target, true)
	s.Observe("", "", "StackDiskLow", "critical", "platform disk is nearly full", true)
	s.Observe("acme", "dev-a", "HighCPU", "critical", "dev-a cpu high", true)

	signals := func(tenant string, cross bool) map[string]bool {
		t.Helper()
		eps, _, _ := s.List(EpisodeScopeFor(tenant, cross), EpisodeQuery{Status: "all", Limit: episodeMaxQueryLimit})
		out := map[string]bool{}
		for _, ep := range eps {
			out[ep.Signal] = true
			if tenant == "globex" && strings.Contains(ep.Summary, "shop.acme.example") {
				t.Errorf("TENANT LEAK: globex was served %q", ep.Summary)
			}
		}
		return out
	}

	other := signals("globex", false)
	if other["ExperienceLatencyOverBudget"] {
		t.Error("a device-less episode OWNED by acme was listed for globex")
	}
	if !other["StackDiskLow"] {
		t.Error("a device-less episode nobody owns must stay visible to every tenant")
	}
	if other["HighCPU"] {
		t.Error("acme's device episode was listed for globex")
	}

	own := signals("acme", false)
	for _, want := range []string{"ExperienceLatencyOverBudget", "StackDiskLow", "HighCPU"} {
		if !own[want] {
			t.Errorf("the owning tenant lost sight of its own %q episode", want)
		}
	}

	all := signals("", true)
	if len(all) != 3 {
		t.Errorf("the platform owner sees %d signals, want 3", len(all))
	}
}

// TestEpisodeListOrderIsATotalOrderNotJustAKeyOrder pins the tie-break.
//
// sort.Slice is not stable, so before this the order of two episodes sharing a
// LastSeen was arbitrary per call — and since List truncates at the limit AFTER
// sorting, which row survived a tie was arbitrary too. A caller could see a row
// appear, vanish, or land on two pages with no data change. This asserts the
// order is a function of the data alone, and that the tie-break reaches the
// truncation boundary rather than only the full list.
func TestEpisodeListOrderIsATotalOrderNotJustAKeyOrder(t *testing.T) {
	same := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	s := NewEpisodeStore(filepath.Join(t.TempDir(), "episodes.json"), 15*time.Minute, 4, 10*time.Minute)
	s.SetNowForTest(func() time.Time { return same.Add(time.Hour) })
	// Insert in an order that is NOT the sorted order, so a no-op sort fails.
	for _, id := range []string{"ep-c", "ep-a", "ep-d", "ep-b"} {
		s.mu.Lock()
		s.episodes[id] = &Episode{ID: id, TenantID: "t1", LastSeen: same, Status: "active"}
		s.mu.Unlock()
	}
	sc := EpisodeScope{Tenant: "t1"}

	var first []string
	for i := 0; i < 12; i++ {
		eps, total, _ := s.List(sc, EpisodeQuery{})
		got := make([]string, len(eps))
		for j, e := range eps {
			got[j] = e.ID
		}
		if total != 4 {
			t.Fatalf("total = %d, want 4", total)
		}
		if i == 0 {
			first = got
			if want := []string{"ep-a", "ep-b", "ep-c", "ep-d"}; strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("tied LastSeen must fall back to id ascending: got %v, want %v", got, want)
			}
			continue
		}
		if strings.Join(got, ",") != strings.Join(first, ",") {
			t.Fatalf("call %d returned a different order for identical data: %v then %v", i, first, got)
		}
	}

	// The tie-break must survive truncation: the same two rows every time.
	for i := 0; i < 12; i++ {
		eps, _, truncated := s.List(sc, EpisodeQuery{Limit: 2})
		if !truncated || len(eps) != 2 {
			t.Fatalf("limit 2: got %d rows truncated=%v", len(eps), truncated)
		}
		if eps[0].ID != "ep-a" || eps[1].ID != "ep-b" {
			t.Fatalf("truncation picked an arbitrary pair on call %d: %s,%s", i, eps[0].ID, eps[1].ID)
		}
	}
}
