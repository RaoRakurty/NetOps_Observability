// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package alerts

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"netops/backend/models"
	"netops/backend/notify"
)

// fakeClock advances manually so `for` gating can be tested across ticks.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// newTestEngine wires an engine to a canned evaluator and a fake clock; no
// rules file, no notifier, no HTTP.
func newTestEngine(t *testing.T, eval func(Rule) ([]Sample, error)) (*Engine, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	e := NewEngine("", nil)
	e.evalFn = eval
	e.now = clock.now
	return e, clock
}

func TestForGatingHoldsUntilDurationElapses(t *testing.T) {
	firing := true
	e, clock := newTestEngine(t, func(Rule) ([]Sample, error) {
		if !firing {
			return nil, nil
		}
		return []Sample{{Labels: map[string]string{"device": "leaf1"}, Value: 99}}, nil
	})
	e.AddRule(Rule{Name: "HighCPU", Expr: "x > 90", For: 60 * time.Second, Severity: "warning"})

	e.evaluateAll() // t=0: condition starts holding → pending, not active
	if n := len(e.Active()); n != 0 {
		t.Fatalf("alert active immediately despite for=60s (got %d active)", n)
	}

	clock.advance(30 * time.Second)
	e.evaluateAll() // t=30s: still pending
	if n := len(e.Active()); n != 0 {
		t.Fatalf("alert active at 30s despite for=60s (got %d active)", n)
	}

	clock.advance(30 * time.Second)
	e.evaluateAll() // t=60s: held for the full duration → active
	active := e.Active()
	if len(active) != 1 {
		t.Fatalf("expected 1 active alert after for elapsed, got %d", len(active))
	}
	if active[0].Rule != "HighCPU" || active[0].DeviceID != "leaf1" {
		t.Fatalf("unexpected alert: %+v", active[0])
	}

	firing = false
	e.evaluateAll() // condition cleared → resolves
	if n := len(e.Active()); n != 0 {
		t.Fatalf("alert did not resolve after condition cleared (got %d)", n)
	}
}

func TestForGatingResetsWhenConditionFlaps(t *testing.T) {
	firing := true
	e, clock := newTestEngine(t, func(Rule) ([]Sample, error) {
		if !firing {
			return nil, nil
		}
		return []Sample{{Labels: map[string]string{"device": "leaf1"}, Value: 1}}, nil
	})
	e.AddRule(Rule{Name: "Flappy", Expr: "x", For: 60 * time.Second, Severity: "warning"})

	e.evaluateAll() // start holding
	clock.advance(45 * time.Second)
	firing = false
	e.evaluateAll() // condition drops at 45s — pending clock must reset
	firing = true
	clock.advance(30 * time.Second)
	e.evaluateAll() // holding again, but only since this tick
	if n := len(e.Active()); n != 0 {
		t.Fatalf("flapping condition fired without re-holding the full for window (got %d)", n)
	}
	clock.advance(60 * time.Second)
	e.evaluateAll()
	if n := len(e.Active()); n != 1 {
		t.Fatalf("expected alert after re-holding for window, got %d", n)
	}
}

func TestForZeroFiresImmediately(t *testing.T) {
	e, _ := newTestEngine(t, func(Rule) ([]Sample, error) {
		return []Sample{{Labels: map[string]string{"device": "leaf1"}, Value: 1}}, nil
	})
	e.AddRule(Rule{Name: "Now", Expr: "x", Severity: "critical"})
	e.evaluateAll()
	if n := len(e.Active()); n != 1 {
		t.Fatalf("for=0 rule should fire on first tick, got %d active", n)
	}
}

func TestRemoveRule(t *testing.T) {
	e, _ := newTestEngine(t, func(Rule) ([]Sample, error) { return nil, nil })
	e.AddRule(Rule{Name: "a", Expr: "x"})
	e.AddRule(Rule{Name: "b", Expr: "y"})
	if !e.RemoveRule("a") {
		t.Fatal("RemoveRule(a) = false, want true")
	}
	if e.RemoveRule("a") {
		t.Fatal("RemoveRule(a) twice = true, want false")
	}
	rules := e.Rules()
	if len(rules) != 1 || rules[0].Name != "b" {
		t.Fatalf("rules after remove = %+v, want just b", rules)
	}
}

func TestRuleJSONForSeconds(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{`{"name":"r","expr":"x","for":300}`, 300 * time.Second},
		{`{"name":"r","expr":"x","for":0.5}`, 500 * time.Millisecond},
		{`{"name":"r","expr":"x","for":"5m"}`, 5 * time.Minute},
		{`{"name":"r","expr":"x"}`, 0},
		{`{"name":"r","expr":"x","for":null}`, 0},
	}
	for _, c := range cases {
		var r Rule
		if err := json.Unmarshal([]byte(c.in), &r); err != nil {
			t.Fatalf("unmarshal %s: %v", c.in, err)
		}
		if r.For != c.want {
			t.Errorf("unmarshal %s: For = %v, want %v", c.in, r.For, c.want)
		}
	}

	// Round trip: marshal emits seconds, not nanoseconds.
	b, err := json.Marshal(Rule{Name: "r", Expr: "x", For: 5 * time.Minute, Severity: "warning"})
	if err != nil {
		t.Fatal(err)
	}
	var back Rule
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.For != 5*time.Minute {
		t.Fatalf("round trip For = %v, want 5m (payload %s)", back.For, b)
	}

	for _, bad := range []string{
		`{"name":"r","expr":"x","for":-1}`,
		`{"name":"r","expr":"x","for":"yesterday"}`,
		`{"name":"r","expr":"x","for":[1]}`,
	} {
		var r Rule
		if err := json.Unmarshal([]byte(bad), &r); err == nil {
			t.Errorf("unmarshal %s: expected error, got For=%v", bad, r.For)
		}
	}
}

// fakeResolveChannel records triggers + resolves so the engine's resolution
// leg (fire → clear → DispatchResolve) is observable through a real Dispatcher.
type fakeResolveChannel struct {
	mu       sync.Mutex
	sent     []string
	resolved []string
}

func (f *fakeResolveChannel) Name() string { return "fake" }
func (f *fakeResolveChannel) Send(a models.Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, a.ID)
	return nil
}
func (f *fakeResolveChannel) SendResolve(a models.Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved = append(f.resolved, a.ID)
	return nil
}

// TestEngineDispatchesResolutions pins the resolution leg (2026-07-11: without
// it, PagerDuty incidents for cleared alerts stayed open forever and piled up):
// an alert that fires notifies once; when its series stops matching, the SAME
// alert id is resolved exactly once, and a steady alert resolves nothing.
func TestEngineDispatchesResolutions(t *testing.T) {
	firing := true
	ch := &fakeResolveChannel{}
	d := notify.NewDispatcher()
	d.Register(ch)
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	e := NewEngine("", d)
	e.evalFn = func(Rule) ([]Sample, error) {
		if !firing {
			return nil, nil
		}
		return []Sample{{Labels: map[string]string{"device": "leaf1"}, Value: 99}}, nil
	}
	e.now = clock.now
	e.AddRule(Rule{Name: "LinkDown", Expr: "x > 0", Severity: "critical"})

	waitFor := func(want func() bool) {
		t.Helper()
		for i := 0; i < 100; i++ {
			ch.mu.Lock()
			ok := want()
			ch.mu.Unlock()
			if ok {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("dispatcher goroutines did not deliver in time (sent=%v resolved=%v)", ch.sent, ch.resolved)
	}

	e.evaluateAll() // fires
	waitFor(func() bool { return len(ch.sent) == 1 })
	e.evaluateAll() // steady — no re-send, no resolve
	clock.advance(30 * time.Second)

	firing = false
	e.evaluateAll() // cleared → resolve dispatched with the same id
	waitFor(func() bool { return len(ch.resolved) == 1 })
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if len(ch.sent) != 1 || ch.resolved[0] != ch.sent[0] {
		t.Fatalf("resolve must target the fired alert exactly once: sent=%v resolved=%v", ch.sent, ch.resolved)
	}
}

// TestOnTransitionFiresOnFireAndResolve asserts the episode hook sees exactly
// the state TRANSITIONS (fire once, resolve once) — never steady-state ticks.
func TestOnTransitionFiresOnFireAndResolve(t *testing.T) {
	firing := true
	e, _ := newTestEngine(t, func(Rule) ([]Sample, error) {
		if !firing {
			return nil, nil
		}
		return []Sample{{Labels: map[string]string{"device": "leaf1"}, Value: 99}}, nil
	})
	e.AddRule(Rule{Name: "LinkDown", Expr: "x > 0", Severity: "critical"})

	var mu sync.Mutex
	type transition struct {
		id     string
		firing bool
	}
	var got []transition
	e.OnTransition = func(a models.Alert, f bool) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, transition{a.ID, f})
	}

	e.evaluateAll() // fires → one firing transition
	e.evaluateAll() // steady → no transition
	firing = false
	e.evaluateAll() // resolves → one clearing transition

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || !got[0].firing || got[1].firing || got[0].id != got[1].id {
		t.Fatalf("want [fire, resolve] for one id, got %+v", got)
	}
}

// TestSuppressNotifySkipsDispatchButNotOnFire asserts a suppressed firing (a)
// sends NO notification, (b) still runs OnFire (incident ingest is not a
// notification), (c) stays in the active set, and (d) emits no dangling
// resolve notification when it clears.
func TestSuppressNotifySkipsDispatchButNotOnFire(t *testing.T) {
	firing := true
	d := notify.NewDispatcher()
	ch := &fakeResolveChannel{}
	d.Register(ch)
	e := NewEngine("", d)
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	e.now = clock.now
	e.evalFn = func(Rule) ([]Sample, error) {
		if !firing {
			return nil, nil
		}
		return []Sample{{Labels: map[string]string{"device": "leaf1"}, Value: 99}}, nil
	}
	e.AddRule(Rule{Name: "LinkDown", Expr: "x > 0", Severity: "critical"})
	e.SuppressNotify = func(models.Alert) bool { return true }
	onFire := 0
	e.OnFire = func(models.Alert) { onFire++ }

	e.evaluateAll() // fires, suppressed
	if n := len(e.Active()); n != 1 {
		t.Fatalf("suppression must not remove the alert from the active set (got %d)", n)
	}
	if onFire != 1 {
		t.Fatalf("OnFire must still run for a suppressed firing (got %d)", onFire)
	}
	firing = false
	e.evaluateAll() // clears — fire was never notified, so resolve must not be either
	time.Sleep(50 * time.Millisecond)
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if len(ch.sent) != 0 || len(ch.resolved) != 0 {
		t.Fatalf("suppressed episode leaked notifications: sent=%v resolved=%v", ch.sent, ch.resolved)
	}
}

// TestUnsuppressedFireStillResolves guards the no-regression path: with a
// SuppressNotify hook installed that does NOT suppress, fire and resolve both
// dispatch exactly as before.
func TestUnsuppressedFireStillResolves(t *testing.T) {
	firing := true
	d := notify.NewDispatcher()
	ch := &fakeResolveChannel{}
	d.Register(ch)
	e := NewEngine("", d)
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	e.now = clock.now
	e.evalFn = func(Rule) ([]Sample, error) {
		if !firing {
			return nil, nil
		}
		return []Sample{{Labels: map[string]string{"device": "leaf1"}, Value: 99}}, nil
	}
	e.AddRule(Rule{Name: "LinkDown", Expr: "x > 0", Severity: "critical"})
	e.SuppressNotify = func(models.Alert) bool { return false }

	waitFor := func(want func() bool) {
		t.Helper()
		for i := 0; i < 100; i++ {
			ch.mu.Lock()
			ok := want()
			ch.mu.Unlock()
			if ok {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("dispatcher goroutines did not deliver in time (sent=%v resolved=%v)", ch.sent, ch.resolved)
	}
	e.evaluateAll()
	waitFor(func() bool { return len(ch.sent) == 1 })
	firing = false
	e.evaluateAll()
	waitFor(func() bool { return len(ch.resolved) == 1 })
}
