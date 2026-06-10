package alerts

import (
	"encoding/json"
	"testing"
	"time"
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
