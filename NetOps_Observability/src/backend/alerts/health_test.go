package alerts

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/models"
	"netops/backend/notify"
)

// TestEvalErrorHoldsAlertsAndReportsUnhealthy is the regression test for the
// class this package was blind to: an eval ERROR was treated as "the rule is
// not firing". Because evaluateAll rebuilds the active set every tick and
// resolves anything absent from it, a VictoriaMetrics outage RESOLVED every
// live alert (closing the PagerDuty incidents the engine had opened) and then
// re-paged on recovery — while Health() kept reporting healthy, because
// `healthy` was set true at construction and never written again.
//
// The tick where the metric store is down must therefore:
//  1. keep the rule's existing alerts active (nothing is known to have cleared),
//  2. dispatch NO resolve notification and no clearing transition,
//  3. count the failure where it can be read from outside the package, and
//  4. report the engine unhealthy.
func TestEvalErrorHoldsAlertsAndReportsUnhealthy(t *testing.T) {
	var evalErr error
	ch := &fakeResolveChannel{}
	d := notify.NewDispatcher()
	d.Register(ch)
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	e := NewEngine("", d)
	e.now = clock.now
	e.evalFn = func(Rule) ([]Sample, error) {
		if evalErr != nil {
			return nil, evalErr
		}
		return []Sample{{Labels: map[string]string{"device": "leaf1"}, Value: 99}}, nil
	}
	e.AddRule(Rule{Name: "LinkDown", Expr: "up == 0", Severity: "critical"})

	var transitions []bool
	e.OnTransition = func(_ models.Alert, firing bool) { transitions = append(transitions, firing) }

	e.evaluateAll() // fires normally
	if n := len(e.Active()); n != 1 {
		t.Fatalf("setup: expected 1 active alert, got %d", n)
	}
	waitForDispatch(t, ch, func() bool { return len(ch.sent) == 1 })
	fired := e.Active()[0]

	// The metric store goes away for two consecutive ticks.
	evalErr = errors.New("dial victoria:8428: connection refused")
	clock.advance(30 * time.Second)
	e.evaluateAll()
	clock.advance(30 * time.Second)
	e.evaluateAll()

	// (1) the alert must still be active, with its ORIGINAL fire time.
	active := e.Active()
	if len(active) != 1 {
		t.Fatalf("a metric-store outage resolved live alerts: %d active, want 1", len(active))
	}
	if active[0].ID != fired.ID || !active[0].FiredAt.Equal(fired.FiredAt) {
		t.Fatalf("held alert was rewritten: got %+v, want %+v", active[0], fired)
	}

	// (2) no resolve notification, no clearing transition.
	time.Sleep(50 * time.Millisecond) // give the dispatcher goroutines a chance to be wrong
	ch.mu.Lock()
	resolved := append([]string(nil), ch.resolved...)
	ch.mu.Unlock()
	if len(resolved) != 0 {
		t.Fatalf("eval failure dispatched resolve notifications (would close live PagerDuty incidents): %v", resolved)
	}
	for i, firing := range transitions {
		if i > 0 && !firing {
			t.Fatalf("eval failure emitted a clearing transition: %v", transitions)
		}
	}

	// (3) the failure is counted, per-rule and in total.
	if got := e.EvalFailures(); got != 2 {
		t.Errorf("EvalFailures() = %d, want 2", got)
	}
	if got := e.RuleEvalFailures()["LinkDown"]; got != 2 {
		t.Errorf("RuleEvalFailures()[LinkDown] = %d, want 2", got)
	}

	// (4) health is falsifiable and reports why.
	h := e.Health()
	if h["healthy"] != false {
		t.Fatalf("Health() reports healthy while every rule is failing: %+v", h)
	}
	if s, _ := h["last_eval_error"].(string); !strings.Contains(s, "connection refused") {
		t.Errorf("Health()[last_eval_error] = %q, want the transport error", s)
	}
	if got, _ := h["eval_failures"].(uint64); got != 2 {
		t.Errorf("Health()[eval_failures] = %v, want 2", h["eval_failures"])
	}

	// Recovery: the first clean tick restores health, keeps the alert, and still
	// dispatches nothing new (the alert never stopped being active).
	evalErr = nil
	clock.advance(30 * time.Second)
	e.evaluateAll()
	if h := e.Health(); h["healthy"] != true {
		t.Fatalf("engine did not recover after a clean tick: %+v", h)
	}
	if n := len(e.Active()); n != 1 {
		t.Fatalf("alert lost across recovery: %d active", n)
	}
	ch.mu.Lock()
	defer ch.mu.Unlock()
	if len(ch.sent) != 1 {
		t.Fatalf("recovery re-paged an alert that never cleared: sent=%v", ch.sent)
	}
}

// TestEvalErrorPreservesPendingClock: a rule still inside its `for` window must
// not lose the time it has already held because the store blipped — otherwise a
// flapping metric store indefinitely postpones a genuine alert.
func TestEvalErrorPreservesPendingClock(t *testing.T) {
	var evalErr error
	e, clock := newTestEngine(t, func(Rule) ([]Sample, error) {
		if evalErr != nil {
			return nil, evalErr
		}
		return []Sample{{Labels: map[string]string{"device": "leaf1"}, Value: 1}}, nil
	})
	e.AddRule(Rule{Name: "Slow", Expr: "x", For: 60 * time.Second, Severity: "warning"})

	e.evaluateAll() // t=0: pending starts
	evalErr = errors.New("store down")
	clock.advance(30 * time.Second)
	e.evaluateAll() // t=30s: blind tick — pending must be carried, not dropped
	evalErr = nil
	clock.advance(30 * time.Second)
	e.evaluateAll() // t=60s: the condition has held the full window
	if n := len(e.Active()); n != 1 {
		t.Fatalf("blind tick reset the pending clock: %d active at t=60s, want 1", n)
	}
}

// TestSingleBrokenRuleIsCountedNotFatal documents the health rule's other half:
// ONE bad expression among many is a minority failure, so it must be counted
// and named — but it must not declare the whole engine down.
func TestSingleBrokenRuleIsCountedNotFatal(t *testing.T) {
	e, clock := newTestEngine(t, func(r Rule) ([]Sample, error) {
		if r.Name == "Broken" {
			return nil, errors.New("victoria 422: unsupported function")
		}
		return nil, nil
	})
	e.AddRule(Rule{Name: "Broken", Expr: "nonsense("})
	e.AddRule(Rule{Name: "Fine1", Expr: "up == 0"})
	e.AddRule(Rule{Name: "Fine2", Expr: "up == 1"})

	for i := 0; i < 3; i++ {
		e.evaluateAll()
		clock.advance(30 * time.Second)
	}
	h := e.Health()
	if h["healthy"] != true {
		t.Errorf("one broken rule out of three declared the whole engine down: %+v", h)
	}
	if got := e.RuleEvalFailures()["Broken"]; got != 3 {
		t.Errorf("RuleEvalFailures()[Broken] = %d, want 3 — a permanently broken rule must be countable", got)
	}
	if got := e.EvalFailures(); got != 3 {
		t.Errorf("EvalFailures() = %d, want 3", got)
	}
	if s, _ := h["last_eval_error"].(string); !strings.Contains(s, "Broken") {
		t.Errorf("Health()[last_eval_error] = %q, want it to name the broken rule", s)
	}
}

// TestRulesFileLoadFailureIsSurfaced: an unreadable RULES_FILE used to start the
// engine with zero rules and a clean bill of health.
func TestRulesFileLoadFailureIsSurfaced(t *testing.T) {
	// A directory is an unreadable "file" regardless of uid — os.ReadFile fails
	// with EISDIR even for root, unlike a chmod-000 file.
	e := NewEngine(t.TempDir(), nil)
	err := e.loadRulesFile()
	if err == nil {
		t.Fatal("loadRulesFile() = nil for an unreadable rules file")
	}
	h := e.Health()
	if h["healthy"] != false {
		t.Errorf("engine healthy after failing to load its rules: %+v", h)
	}
	if s, _ := h["rules_load_error"].(string); s == "" {
		t.Errorf("Health()[rules_load_error] empty after a load failure: %+v", h)
	}
	if n := len(e.Rules()); n != 0 {
		t.Errorf("rules = %d, want 0", n)
	}
	// A failed load stays visible: evaluating cleanly must not paper over it.
	e.evalFn = func(Rule) ([]Sample, error) { return nil, nil }
	e.evaluateAll()
	if h := e.Health(); h["healthy"] != false {
		t.Errorf("a clean tick cleared a rules-file load failure: %+v", h)
	}
}

// TestLoadRulesRejectsMalformedRule: a rule that lost its expr is rejected at
// LOAD time, naming the rule, and never enters the engine — it used to load and
// then error on every tick forever.
func TestLoadRulesRejectsMalformedRule(t *testing.T) {
	const yaml = `
groups:
  - name: g
    rules:
      - alert: Good
        expr: up == 0
        labels: { severity: critical }
      - alert: LostItsExpr
        for: 5m
        labels: { severity: warning }
      - alert: EmptyFold
        expr: >
        labels: { severity: warning }
`
	rules, err := parseRulesYAML(yaml)
	if err == nil {
		t.Fatal("parseRulesYAML accepted a rule with no expr")
	}
	for _, name := range []string{"LostItsExpr", "EmptyFold"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name the rejected rule %q", err, name)
		}
	}
	if len(rules) != 1 || rules[0].Name != "Good" {
		t.Fatalf("valid rules must still load: got %+v", rules)
	}

	// Through the file path the engine actually uses.
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(path, nil)
	if err := e.loadRulesFile(); err == nil {
		t.Fatal("loadRulesFile() = nil for a file with a malformed rule")
	}
	if n := len(e.Rules()); n != 1 {
		t.Fatalf("engine loaded %d rules, want just the valid one", n)
	}
	if h := e.Health(); h["healthy"] != false {
		t.Errorf("engine healthy with a rejected rule in its file: %+v", h)
	}
}

// TestParseRulesUnnamedRuleRejected: an `- alert:` with no name yields an id-less
// rule whose alerts could never be addressed.
func TestParseRulesUnnamedRuleRejected(t *testing.T) {
	rules, err := parseRulesYAML("groups:\n  - name: g\n    rules:\n      - alert:\n        expr: up == 0\n")
	if err == nil {
		t.Fatalf("unnamed rule accepted: %+v", rules)
	}
	if len(rules) != 0 {
		t.Fatalf("unnamed rule loaded anyway: %+v", rules)
	}
}

// waitForDispatch polls until want() holds; the Dispatcher delivers on its own
// goroutines.
func waitForDispatch(t *testing.T, ch *fakeResolveChannel, want func() bool) {
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
	t.Fatalf("dispatcher did not deliver in time (sent=%v resolved=%v)", ch.sent, ch.resolved)
}
