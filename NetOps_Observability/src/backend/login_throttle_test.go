package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/alerts"
)

// login_throttle_test.go — F-25 FAILURE-PATH tests.
//
// The pre-fix throttle passed every happy-path test it had: lock after N
// failures, unlock after the window, clear on success. All of those stayed
// green while the map silently stopped counting at 50,000 entries. These tests
// therefore exercise only the exhaustion and fault paths.

// newTestThrottle returns a throttle with a small cap and a controllable clock,
// so exhaustion is reachable in a unit test without allocating 50k entries.
func newTestThrottle(max int, now func() time.Time) *loginThrottle {
	return &loginThrottle{
		entries: map[string]*throttleEntry{},
		max:     max,
		window:  throttleTrackWindow,
		now:     now,
	}
}

// TestThrottleDoesNotFailOpenUnderSpray is the F-25 regression proper: after the
// map is filled with junk usernames, a REAL account must still lock out. The old
// code returned early at the cap, so the real account was never tracked and
// could be guessed forever.
func TestThrottleDoesNotFailOpenUnderSpray(t *testing.T) {
	base := time.Now()
	clock := base
	th := newTestThrottle(64, func() time.Time { return clock })

	// Spray the cap full of junk usernames (one failure each — below any
	// lockout threshold, so none of them locks).
	for i := 0; i < 200; i++ {
		if !th.fail(fmt.Sprintf("junk-%d@spray", i), 5, 300) {
			t.Fatalf("spray attempt %d refused — the throttle must keep counting, not saturate on unlocked junk", i)
		}
		clock = clock.Add(time.Millisecond)
	}
	if got := th.size(); got > 64 {
		t.Fatalf("throttle grew past its cap: %d entries (memory bound broken)", got)
	}
	if th.evictions.Load() == 0 {
		t.Fatal("no evictions recorded — the cap was held by refusing to track, i.e. by failing open")
	}

	// Now brute-force a real account through the full spray.
	const victim = "admin"
	for i := 0; i < 5; i++ {
		if !th.fail(victim, 5, 300) {
			t.Fatalf("victim failure %d was not counted", i+1)
		}
		clock = clock.Add(time.Millisecond)
	}
	locked, d := th.locked(victim)
	if !locked {
		t.Fatal("FAIL-OPEN: the real account did not lock after 5 failures while the map was full — " +
			"this is exactly the F-25 brute-force bypass (spray 50k usernames, then guess freely)")
	}
	if d <= 0 {
		t.Fatalf("locked but with no remaining time: %v", d)
	}
}

// TestThrottleNeverEvictsALiveLock: if a locked entry were evictable, the spray
// would become an UNLOCK primitive — flood the map and the account you are
// attacking is released early.
func TestThrottleNeverEvictsALiveLock(t *testing.T) {
	base := time.Now()
	clock := base
	th := newTestThrottle(8, func() time.Time { return clock })

	const victim = "admin"
	for i := 0; i < 3; i++ {
		th.fail(victim, 3, 600)
	}
	if locked, _ := th.locked(victim); !locked {
		t.Fatal("setup: victim should be locked")
	}
	// Hammer with far more distinct usernames than the cap.
	for i := 0; i < 500; i++ {
		th.fail(fmt.Sprintf("junk-%d", i), 5, 300)
		clock = clock.Add(time.Millisecond)
	}
	if locked, _ := th.locked(victim); !locked {
		t.Fatal("a username spray released the victim's lock — eviction must never touch a live lock")
	}
}

// TestThrottleFailsClosedWhenFullyLocked: the one case where there is genuinely
// no room (every slot is a live lock) must REFUSE the attempt and count it, not
// wave it through uncounted.
func TestThrottleFailsClosedWhenFullyLocked(t *testing.T) {
	base := time.Now()
	clock := base
	th := newTestThrottle(4, func() time.Time { return clock })

	for i := 0; i < 4; i++ {
		u := fmt.Sprintf("locked-%d", i)
		if !th.fail(u, 1, 600) { // allowed=1 → locks immediately
			t.Fatalf("setup: %s should have been tracked", u)
		}
	}
	if th.size() != 4 {
		t.Fatalf("setup: expected 4 locked entries, got %d", th.size())
	}
	if th.fail("newcomer", 5, 300) {
		t.Fatal("FAIL-OPEN: an untrackable failure was reported as counted — the caller would serve an unlimited guess")
	}
	if th.saturation.Load() == 0 {
		t.Fatal("saturation was not counted — the whole defect was that this state is invisible (§10)")
	}

	// It must self-heal: once the locks expire, tracking resumes.
	clock = clock.Add(601 * time.Second)
	if !th.fail("newcomer", 5, 300) {
		t.Fatal("throttle stayed saturated after every lock expired — that is a permanent self-inflicted login outage")
	}
}

// TestThrottleSweepsStaleEntries: the original had NO deletion path for an entry
// with fails<allowed and no lock, so the map could only grow for the life of the
// process.
func TestThrottleSweepsStaleEntries(t *testing.T) {
	base := time.Now()
	clock := base
	th := newTestThrottle(1000, func() time.Time { return clock })

	for i := 0; i < 100; i++ {
		th.fail(fmt.Sprintf("stale-%d", i), 5, 300)
	}
	th.fail("recent", 5, 300)
	if th.size() != 101 {
		t.Fatalf("setup: expected 101 entries, got %d", th.size())
	}

	clock = clock.Add(throttleTrackWindow + time.Minute)
	th.fail("recent", 5, 300) // refresh one entry at the new time
	th.sweep()

	if th.size() != 1 {
		t.Fatalf("sweep left %d entries; only the freshly-touched one should survive", th.size())
	}
	if th.sweeps.Load() != 100 {
		t.Fatalf("swept counter = %d, want 100 — reclaimed memory must be observable", th.sweeps.Load())
	}
}

// TestThrottleJanitorStopsOnContextCancel: a background sweeper that ignores
// cancellation is a shutdown-drain defect of its own.
func TestThrottleJanitorStopsOnContextCancel(t *testing.T) {
	th := newLoginThrottle()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { th.runJanitor(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("janitor did not return on context cancellation")
	}
}

// TestThrottleConcurrentSprayIsRaceFree exercises the cap/evict/sweep paths
// concurrently; run under -race this is the only test that covers the eviction
// scan while other goroutines mutate the map.
func TestThrottleConcurrentSprayIsRaceFree(t *testing.T) {
	th := newTestThrottle(128, time.Now)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				th.fail(fmt.Sprintf("u-%d-%d", g, i), 5, 300)
				th.locked(fmt.Sprintf("u-%d-%d", g, i/2))
				if i%50 == 0 {
					th.sweep()
				}
			}
		}(g)
	}
	wg.Wait()
	if th.size() > 128 {
		t.Fatalf("cap breached under concurrency: %d entries", th.size())
	}
}

// TestLoginRefusesUncountableAttempt wires the fail-closed signal through the
// actual HTTP handler: a saturated throttle must answer 429 with Retry-After,
// never 401 (a 401 is a guess the platform could not count).
func TestLoginRefusesUncountableAttempt(t *testing.T) {
	_, srv := newTestServerState(t)
	srv.loginThrottle = newTestThrottle(2, time.Now)
	// Fill both slots with live locks.
	srv.loginThrottle.fail("locked-a", 1, 600)
	srv.loginThrottle.fail("locked-b", 1, 600)

	body, err := json.Marshal(map[string]string{"username": "someone-else", "password": "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	srv.handleLogin(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 — a failure the throttle cannot count must be refused, not answered 401", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After on the fail-closed refusal — clients cannot back off correctly")
	}
	if srv.loginThrottle.saturation.Load() == 0 {
		t.Error("saturation not counted on the HTTP path")
	}
}

// TestLoginThrottleMetricsExposed: the counters must actually reach /metrics —
// an unexported counter is not observability.
func TestLoginThrottleMetricsExposed(t *testing.T) {
	_, srv := newTestServerState(t)
	srv.alerts = alerts.NewEngine("", nil)
	w := httptest.NewRecorder()
	srv.handlePromMetrics(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	out := w.Body.String()
	for _, want := range []string{
		"netops_login_throttle_accounts",
		"netops_login_throttle_evictions_total",
		"netops_login_throttle_swept_total",
		"netops_login_throttle_saturated_total",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("/metrics is missing %s — F-25's failure mode stays invisible without it", want)
		}
	}
}
