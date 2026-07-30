package cloud

// monitor_eval_test.go — evaluator honesty/transition semantics (no_data ≠ ok,
// store-down = error, notify only on edges). Moved in-package with the
// evaluator (P2 W4.18); the CRUD/authoring HTTP contract stays in main.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"netops/backend/models"
)

// evalHarness builds an evaluator over an in-memory store with injected seams.
func evalHarness(t *testing.T, m Monitor, ids []string,
	q func(ctx context.Context, query string) map[string]float64) (*MonitorEvaluator, *MonitorStore, *[]string) {
	t.Helper()
	store := NewMonitorStore("")
	if fits, err := store.Upsert("t1", m); err != nil || !fits {
		t.Fatal("seed monitor failed")
	}
	var events []string
	e := NewMonitorEvaluator(store, MonitorEvalDeps{
		ResourceIDs: func(context.Context, string) ([]string, error) { return ids, nil },
		Query:       q,
		Fire:        func(a models.Alert) { events = append(events, "fire:"+a.Rule) },
		Resolve:     func(a models.Alert) { events = append(events, "resolve:"+a.Rule) },
		Now:         func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}, time.Minute)
	return e, store, &events
}

func monState(t *testing.T, store *MonitorStore, id string) Monitor {
	t.Helper()
	m, ok := store.Get("t1", id)
	if !ok {
		t.Fatal("monitor vanished")
	}
	return m
}

func TestEvaluatorThresholdTransitions(t *testing.T) {
	def := Monitor{ID: "m1", Name: "High CPU", Metric: "cloud_cpu_util",
		Mode: MonitorModeThreshold, Condition: MonitorCondAbove, Threshold: 90,
		Enabled: true, LastState: MonitorStateNever}
	val := 95.0
	e, store, events := evalHarness(t, def, []string{"i-1", "i-2"},
		func(context.Context, string) map[string]float64 {
			return map[string]float64{"i-1": val, "i-2": 10}
		})

	// Cycle 1: 95 > 90 → firing, one notification.
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != MonitorStateFiring || st.LastValue == nil || *st.LastValue != 95 {
		t.Fatalf("cycle1: %+v", st)
	}
	if len(*events) != 1 || (*events)[0] != "fire:High CPU" {
		t.Fatalf("cycle1 events: %v", *events)
	}

	// Cycle 2: still firing → NO repeat notification.
	e.evaluateAll(context.Background())
	if len(*events) != 1 {
		t.Fatalf("repeat fire notified: %v", *events)
	}

	// Cycle 3: recovered → resolve exactly once.
	val = 50
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != MonitorStateOK {
		t.Fatalf("cycle3: %+v", st)
	}
	if len(*events) != 2 || (*events)[1] != "resolve:High CPU" {
		t.Fatalf("cycle3 events: %v", *events)
	}
}

func TestEvaluatorHonestStates(t *testing.T) {
	def := Monitor{ID: "m1", Name: "n", Metric: "cloud_cpu_util",
		Mode: MonitorModeThreshold, Condition: MonitorCondAbove, Threshold: 90,
		Enabled: true, LastState: MonitorStateNever}

	// Store unreachable → error, not ok.
	e, store, events := evalHarness(t, def, []string{"i-1"},
		func(context.Context, string) map[string]float64 { return nil })
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != MonitorStateError {
		t.Fatalf("store-down: %+v", st)
	}
	if len(*events) != 0 {
		t.Fatalf("error must not notify: %v", *events)
	}

	// No samples → no_data with the reason named.
	e, store, _ = evalHarness(t, def, []string{"i-1"},
		func(context.Context, string) map[string]float64 { return map[string]float64{} })
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != MonitorStateNoData || st.LastReason == "" {
		t.Fatalf("no-samples: %+v", st)
	}

	// No resources in inventory → no_data.
	e, store, _ = evalHarness(t, def, nil,
		func(context.Context, string) map[string]float64 { t.Fatal("must not query"); return nil })
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != MonitorStateNoData {
		t.Fatalf("no-resources: %+v", st)
	}

	// Scoped to a resource that left the inventory → no_data.
	scoped := def
	scoped.ResourceID = "i-gone"
	e, store, _ = evalHarness(t, scoped, []string{"i-1"},
		func(context.Context, string) map[string]float64 { t.Fatal("must not query"); return nil })
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != MonitorStateNoData {
		t.Fatalf("gone-resource: %+v", st)
	}

	// Disabled → disabled, no queries.
	off := def
	off.Enabled = false
	e, store, _ = evalHarness(t, off, []string{"i-1"},
		func(context.Context, string) map[string]float64 { t.Fatal("must not query"); return nil })
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != MonitorStateDisabled {
		t.Fatalf("disabled: %+v", st)
	}
}

func TestEvaluatorAnomaly(t *testing.T) {
	def := Monitor{ID: "m1", Name: "CPU anomaly", Metric: "cloud_cpu_util",
		Mode: MonitorModeAnomaly, Enabled: true, LastState: MonitorStateNever}

	mk := func(last, avg, sd float64) func(context.Context, string) map[string]float64 {
		return func(_ context.Context, q string) map[string]float64 {
			switch {
			case len(q) > 4 && q[:4] == "last":
				return map[string]float64{"i-1": last}
			case len(q) > 3 && q[:3] == "avg":
				return map[string]float64{"i-1": avg}
			default:
				return map[string]float64{"i-1": sd}
			}
		}
	}

	// Within 3σ → ok.
	e, store, _ := evalHarness(t, def, []string{"i-1"}, mk(55, 50, 5))
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != MonitorStateOK {
		t.Fatalf("within-band: %+v", st)
	}

	// 10σ deviation → firing.
	e, store, events := evalHarness(t, def, []string{"i-1"}, mk(100, 50, 5))
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != MonitorStateFiring {
		t.Fatalf("deviation: %+v", st)
	}
	if len(*events) != 1 {
		t.Fatalf("anomaly must notify once: %v", *events)
	}

	// Fresh value but NO baseline history → no_data (needs history, honestly).
	e, store, _ = evalHarness(t, def, []string{"i-1"},
		func(_ context.Context, q string) map[string]float64 {
			if len(q) > 4 && q[:4] == "last" {
				return map[string]float64{"i-1": 100}
			}
			return map[string]float64{}
		})
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != MonitorStateNoData {
		t.Fatalf("no-baseline: %+v", st)
	}
}

func TestEvaluatorScopeCap(t *testing.T) {
	def := Monitor{ID: "m1", Name: "wide", Metric: "cloud_cpu_util",
		Mode: MonitorModeThreshold, Condition: MonitorCondAbove, Threshold: 90,
		Enabled: true, LastState: MonitorStateNever}
	ids := make([]string, monitorMaxScopeIDs+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("i-%d", i)
	}
	e, store, _ := evalHarness(t, def, ids,
		func(context.Context, string) map[string]float64 { t.Fatal("must not query over-cap scope"); return nil })
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != MonitorStateError {
		t.Fatalf("over-cap scope: %+v", st)
	}
}
