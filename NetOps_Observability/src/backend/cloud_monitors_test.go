package main

// cloud_monitors_test.go — unit tests for monitor authoring + the bounded
// evaluator (Wave 5 #14 slice 3): closed-vocabulary validation, CRUD contract,
// and evaluator honesty/transition semantics (no_data ≠ ok, store-down =
// error, notify only on edges).

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"

	"netops/backend/models"

	"netops/backend/cloud"
)

func TestNormalizeCloudMonitor(t *testing.T) {
	good := cloudMonitor{Name: "High CPU", Metric: "cloud_cpu_util", Mode: cloud.MonitorModeThreshold, Condition: cloud.MonitorCondAbove, Threshold: 90, Enabled: true}
	m, err := cloud.NormalizeMonitor(good)
	if err != nil || m.Name != "High CPU" || !m.Enabled {
		t.Fatalf("valid monitor refused: %v %+v", err, m)
	}
	anomaly := cloudMonitor{Name: "CPU anomaly", Metric: "cloud_cpu_util", Mode: cloud.MonitorModeAnomaly, Enabled: true}
	if _, err := cloud.NormalizeMonitor(anomaly); err != nil {
		t.Fatalf("valid anomaly monitor refused: %v", err)
	}
	bad := []cloudMonitor{
		{Name: "", Metric: "cloud_cpu_util", Mode: cloud.MonitorModeThreshold, Condition: cloud.MonitorCondAbove},
		{Name: "x", Metric: "up", Mode: cloud.MonitorModeThreshold, Condition: cloud.MonitorCondAbove},                                    // metric outside catalog
		{Name: "x", Metric: `cloud_cpu_util{a="b"}`, Mode: cloud.MonitorModeThreshold, Condition: cloud.MonitorCondAbove},                 // selector injection
		{Name: "x", Metric: "cloud_cpu_util", Mode: "sideways", Condition: cloud.MonitorCondAbove},                                        // bad mode
		{Name: "x", Metric: "cloud_cpu_util", Mode: cloud.MonitorModeThreshold, Condition: "equals"},                                      // bad condition
		{Name: "x", Metric: "cloud_cpu_util", Mode: cloud.MonitorModeThreshold, Condition: cloud.MonitorCondAbove, Threshold: math.NaN()}, // NaN
		{Name: "x", Metric: "cloud_cpu_util", Mode: cloud.MonitorModeAnomaly, Threshold: 5},                                               // leftover threshold
		{Name: "x", Metric: "cloud_cpu_util", Mode: cloud.MonitorModeThreshold, Condition: cloud.MonitorCondAbove, ResourceID: `i-"quot`}, // bad resource id
	}
	for i, b := range bad {
		if _, err := cloud.NormalizeMonitor(b); err == nil {
			t.Errorf("case %d accepted: %+v", i, b)
		}
	}
}

func TestCloudMonitorCRUDContract(t *testing.T) {
	srv, s := newTestServerState(t)
	s.cloudMonitors = newCloudMonitorStore("") // in-memory
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st, b := do(t, srv, "POST", "/api/onboard", admin, map[string]any{
		"org_name": "Mon Corp", "tenant_name": "Mon Prod", "tenant_slug": "mon-prod",
	})
	if st != 201 {
		t.Fatalf("onboard: %d %s", st, b)
	}
	var ob onboardResponse
	if err := json.Unmarshal(b, &ob); err != nil {
		t.Fatal(err)
	}
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "monop", "password": "Passw0rd!2345", "role": "operator", "tenant_id": ob.Tenant.ID,
	}); st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	tok := login(t, srv, "monop", "Passw0rd!2345").Token

	// Create — tenant stamped from token even when the body lies.
	st, b = do(t, srv, "POST", "/api/cloud/monitors", tok, map[string]any{
		"name": "High CPU", "metric": "cloud_cpu_util", "mode": "threshold",
		"condition": "above", "threshold": 90, "enabled": true,
		"tenant_id": "someone-else", // must be ignored
	})
	if st != 201 {
		t.Fatalf("create: %d %s", st, b)
	}
	var created cloudMonitor
	if err := json.Unmarshal(b, &created); err != nil {
		t.Fatal(err)
	}
	if created.TenantID != ob.Tenant.ID {
		t.Fatalf("tenant must come from the token, got %q", created.TenantID)
	}
	if created.LastState != cloud.MonitorStateNever {
		t.Fatalf("new monitor must be never_evaluated, got %q", created.LastState)
	}

	// Invalid create → 400.
	if st, _ := do(t, srv, "POST", "/api/cloud/monitors", tok, map[string]any{
		"name": "bad", "metric": "up", "mode": "threshold", "condition": "above",
	}); st != 400 {
		t.Fatalf("catalog violation must be 400, got %d", st)
	}

	// List shows it.
	st, b = do(t, srv, "GET", "/api/cloud/monitors", tok, nil)
	if st != 200 {
		t.Fatalf("list: %d", st)
	}
	var list struct {
		Monitors []cloudMonitor `json:"monitors"`
		Count    int            `json:"count"`
	}
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatal(err)
	}
	if list.Count != 1 || list.Monitors[0].ID != created.ID {
		t.Fatalf("wrong list: %+v", list)
	}

	// Update resets the verdict (definition changed).
	_ = s.cloudMonitors.SetStatus(ob.Tenant.ID, created.ID, cloud.MonitorStateFiring, "was firing", nil, time.Now())
	st, b = do(t, srv, "PUT", "/api/cloud/monitors/"+created.ID, tok, map[string]any{
		"name": "High CPU v2", "metric": "cloud_cpu_util", "mode": "threshold",
		"condition": "above", "threshold": 80, "enabled": true,
	})
	if st != 200 {
		t.Fatalf("update: %d %s", st, b)
	}
	var updated cloudMonitor
	if err := json.Unmarshal(b, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.LastState != cloud.MonitorStateNever || updated.Threshold != 80 {
		t.Fatalf("update must reset verdict: %+v", updated)
	}

	// Delete.
	if st, _ := do(t, srv, "DELETE", "/api/cloud/monitors/"+created.ID, tok, nil); st != 200 {
		t.Fatal("delete failed")
	}
	if st, _ := do(t, srv, "GET", "/api/cloud/monitors/"+created.ID, tok, nil); st != 404 {
		t.Fatal("deleted monitor must be 404")
	}

	// Per-tenant cap.
	for i := 0; i < cloudMonitorsMaxPerTenant; i++ {
		if st, b := do(t, srv, "POST", "/api/cloud/monitors", tok, map[string]any{
			"name": fmt.Sprintf("m-%d", i), "metric": "cloud_cpu_util", "mode": "anomaly", "enabled": true,
		}); st != 201 {
			t.Fatalf("create %d: %d %s", i, st, b)
		}
	}
	if st, _ := do(t, srv, "POST", "/api/cloud/monitors", tok, map[string]any{
		"name": "over-cap", "metric": "cloud_cpu_util", "mode": "anomaly", "enabled": true,
	}); st != 400 {
		t.Fatalf("over-cap create must be 400, got %d", st)
	}
}

// evalHarness builds an evaluator over an in-memory store with injected seams.
func evalHarness(t *testing.T, m cloudMonitor, ids []string,
	q func(ctx context.Context, query string) map[string]float64) (*cloudMonitorEvaluator, *cloudMonitorStore, *[]string) {
	t.Helper()
	store := newCloudMonitorStore("")
	if fits, err := store.Upsert("t1", m); err != nil || !fits {
		t.Fatal("seed monitor failed")
	}
	var events []string
	e := &cloudMonitorEvaluator{
		store:       store,
		resourceIDs: func(context.Context, string) ([]string, error) { return ids, nil },
		queryFn:     q,
		fire:        func(a models.Alert) { events = append(events, "fire:"+a.Rule) },
		resolve:     func(a models.Alert) { events = append(events, "resolve:"+a.Rule) },
		interval:    time.Minute,
		now:         func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
	return e, store, &events
}

func monState(t *testing.T, store *cloudMonitorStore, id string) cloudMonitor {
	t.Helper()
	m, ok := store.Get("t1", id)
	if !ok {
		t.Fatal("monitor vanished")
	}
	return m
}

func TestEvaluatorThresholdTransitions(t *testing.T) {
	def := cloudMonitor{ID: "m1", Name: "High CPU", Metric: "cloud_cpu_util",
		Mode: cloud.MonitorModeThreshold, Condition: cloud.MonitorCondAbove, Threshold: 90,
		Enabled: true, LastState: cloud.MonitorStateNever}
	val := 95.0
	e, store, events := evalHarness(t, def, []string{"i-1", "i-2"},
		func(context.Context, string) map[string]float64 {
			return map[string]float64{"i-1": val, "i-2": 10}
		})

	// Cycle 1: 95 > 90 → firing, one notification.
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != cloud.MonitorStateFiring || st.LastValue == nil || *st.LastValue != 95 {
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
	if st := monState(t, store, "m1"); st.LastState != cloud.MonitorStateOK {
		t.Fatalf("cycle3: %+v", st)
	}
	if len(*events) != 2 || (*events)[1] != "resolve:High CPU" {
		t.Fatalf("cycle3 events: %v", *events)
	}
}

func TestEvaluatorHonestStates(t *testing.T) {
	def := cloudMonitor{ID: "m1", Name: "n", Metric: "cloud_cpu_util",
		Mode: cloud.MonitorModeThreshold, Condition: cloud.MonitorCondAbove, Threshold: 90,
		Enabled: true, LastState: cloud.MonitorStateNever}

	// Store unreachable → error, not ok.
	e, store, events := evalHarness(t, def, []string{"i-1"},
		func(context.Context, string) map[string]float64 { return nil })
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != cloud.MonitorStateError {
		t.Fatalf("store-down: %+v", st)
	}
	if len(*events) != 0 {
		t.Fatalf("error must not notify: %v", *events)
	}

	// No samples → no_data with the reason named.
	e, store, _ = evalHarness(t, def, []string{"i-1"},
		func(context.Context, string) map[string]float64 { return map[string]float64{} })
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != cloud.MonitorStateNoData || st.LastReason == "" {
		t.Fatalf("no-samples: %+v", st)
	}

	// No resources in inventory → no_data.
	e, store, _ = evalHarness(t, def, nil,
		func(context.Context, string) map[string]float64 { t.Fatal("must not query"); return nil })
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != cloud.MonitorStateNoData {
		t.Fatalf("no-resources: %+v", st)
	}

	// Scoped to a resource that left the inventory → no_data.
	scoped := def
	scoped.ResourceID = "i-gone"
	e, store, _ = evalHarness(t, scoped, []string{"i-1"},
		func(context.Context, string) map[string]float64 { t.Fatal("must not query"); return nil })
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != cloud.MonitorStateNoData {
		t.Fatalf("gone-resource: %+v", st)
	}

	// Disabled → disabled, no queries.
	off := def
	off.Enabled = false
	e, store, _ = evalHarness(t, off, []string{"i-1"},
		func(context.Context, string) map[string]float64 { t.Fatal("must not query"); return nil })
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != cloud.MonitorStateDisabled {
		t.Fatalf("disabled: %+v", st)
	}
}

func TestEvaluatorAnomaly(t *testing.T) {
	def := cloudMonitor{ID: "m1", Name: "CPU anomaly", Metric: "cloud_cpu_util",
		Mode: cloud.MonitorModeAnomaly, Enabled: true, LastState: cloud.MonitorStateNever}

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
	if st := monState(t, store, "m1"); st.LastState != cloud.MonitorStateOK {
		t.Fatalf("within-band: %+v", st)
	}

	// 10σ deviation → firing.
	e, store, events := evalHarness(t, def, []string{"i-1"}, mk(100, 50, 5))
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != cloud.MonitorStateFiring {
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
	if st := monState(t, store, "m1"); st.LastState != cloud.MonitorStateNoData {
		t.Fatalf("no-baseline: %+v", st)
	}
}

func TestEvaluatorScopeCap(t *testing.T) {
	def := cloudMonitor{ID: "m1", Name: "wide", Metric: "cloud_cpu_util",
		Mode: cloud.MonitorModeThreshold, Condition: cloud.MonitorCondAbove, Threshold: 90,
		Enabled: true, LastState: cloud.MonitorStateNever}
	ids := make([]string, cloudMonitorMaxScopeIDs+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("i-%d", i)
	}
	e, store, _ := evalHarness(t, def, ids,
		func(context.Context, string) map[string]float64 { t.Fatal("must not query over-cap scope"); return nil })
	e.evaluateAll(context.Background())
	if st := monState(t, store, "m1"); st.LastState != cloud.MonitorStateError {
		t.Fatalf("over-cap scope: %+v", st)
	}
}
