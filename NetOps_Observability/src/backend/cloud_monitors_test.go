// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_monitors_test.go — unit tests for monitor authoring (Wave 5 #14
// slice 3): closed-vocabulary validation + the CRUD contract. The evaluator
// honesty/transition suite moved in-package (cloud/monitor_eval_test.go,
// P2 W4.18).

import (
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"time"

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
