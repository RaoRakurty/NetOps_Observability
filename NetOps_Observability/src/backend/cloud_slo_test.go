// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_slo_test.go — unit tests for the SLO/error-budget slice (Wave 5 #14
// slice 2): validation bounds, budget math, and the honesty contract of the
// measurement (no resources / no samples / store down ⇒ NOT measurable —
// never a fabricated 100%).

import (
	"context"
	"encoding/json"
	"math"
	"netops/backend/cloud"
	"testing"
)

func TestNormalizeCloudSLOs(t *testing.T) {
	good := []cloudSLO{{AppName: "billing-api", TargetPct: 99.9, WindowDays: 30}}
	out, err := cloud.NormalizeSLOs(good)
	if err != nil || len(out) != 1 {
		t.Fatalf("valid slo refused: %v", err)
	}
	bad := [][]cloudSLO{
		nil, // empty
		{{AppName: "", TargetPct: 99.9, WindowDays: 30}},
		{{AppName: "a;drop", TargetPct: 99.9, WindowDays: 30}},
		{{AppName: "ok", TargetPct: 49.9, WindowDays: 30}}, // below floor
		{{AppName: "ok", TargetPct: 100, WindowDays: 30}},  // no budget left
		{{AppName: "ok", TargetPct: math.NaN(), WindowDays: 30}},
		{{AppName: "ok", TargetPct: 99.9, WindowDays: 0}},
		{{AppName: "ok", TargetPct: 99.9, WindowDays: 31}},
		{{AppName: "dup", TargetPct: 99, WindowDays: 7}, {AppName: "DUP", TargetPct: 99, WindowDays: 7}},
	}
	for i, b := range bad {
		if _, err := cloud.NormalizeSLOs(b); err == nil {
			t.Errorf("case %d: invalid slos accepted: %+v", i, b)
		}
	}
	over := make([]cloudSLO, cloudSLOMaxPerTenant+1)
	for i := range over {
		over[i] = cloudSLO{AppName: "app-" + string(rune('a'+i%26)) + string(rune('a'+i/26)), TargetPct: 99, WindowDays: 7}
	}
	if _, err := cloud.NormalizeSLOs(over); err == nil {
		t.Error("over-cap slo list accepted")
	}
}

func TestSloBudget(t *testing.T) {
	// target 99.9, actual 99.95 → half the 0.1 budget spent.
	budget, burn, remaining := cloud.SLOBudget(99.9, 99.95)
	if math.Abs(budget-0.1) > 1e-9 || math.Abs(burn-0.5) > 1e-6 || math.Abs(remaining-50) > 1e-4 {
		t.Fatalf("got budget=%v burn=%v remaining=%v", budget, burn, remaining)
	}
	// Over-spent: remaining floors at 0, burn carries the overshoot.
	_, burn, remaining = cloud.SLOBudget(99.9, 99.5)
	if remaining != 0 || burn < 4.9 {
		t.Fatalf("overspend: burn=%v remaining=%v", burn, remaining)
	}
	// Perfect actual → nothing spent.
	_, burn, remaining = cloud.SLOBudget(99.9, 100)
	if burn != 0 || remaining != 100 {
		t.Fatalf("perfect: burn=%v remaining=%v", burn, remaining)
	}
}

func TestMeasureCloudSLOHonesty(t *testing.T) {
	ctx := context.Background()
	slo := cloudSLO{AppName: "shop", TargetPct: 99.9, WindowDays: 7}

	// 1) No resources attributed → not measurable.
	st := cloud.MeasureSLO(ctx, slo, map[string][]string{}, func(context.Context, string) map[string]float64 {
		t.Fatal("must not query the store when no resources exist")
		return nil
	})
	if st.Measurable || st.ActualPct != 0 {
		t.Fatalf("no resources must be not-measurable: %+v", st)
	}

	idx := map[string][]string{"shop": {"i-1", "i-2"}}

	// 2) Store unreachable (nil) → not measurable, says so.
	st = cloud.MeasureSLO(ctx, slo, idx, func(context.Context, string) map[string]float64 { return nil })
	if st.Measurable {
		t.Fatalf("store-down must be not-measurable: %+v", st)
	}

	// 3) Store up but NO samples → not measurable, never 100%.
	st = cloud.MeasureSLO(ctx, slo, idx, func(context.Context, string) map[string]float64 { return map[string]float64{} })
	if st.Measurable || st.ResourcesReporting != 0 {
		t.Fatalf("no samples must be not-measurable: %+v", st)
	}

	// 4) Real samples: i-1 failed 0.2% of periods, i-2 clean → availability 99.9.
	st = cloud.MeasureSLO(ctx, slo, idx, func(_ context.Context, q string) map[string]float64 {
		return map[string]float64{"i-1": 0.002, "i-2": 0}
	})
	if !st.Measurable || st.ResourcesReporting != 2 {
		t.Fatalf("measured case broken: %+v", st)
	}
	if math.Abs(st.ActualPct-99.9) > 1e-6 {
		t.Fatalf("actual = %v, want 99.9", st.ActualPct)
	}
	// Exactly on target → whole budget burned, nothing left, burn 1.0.
	if math.Abs(st.BurnRatio-1) > 1e-6 || st.BudgetRemainingPct > 1e-6 {
		t.Fatalf("burn=%v remaining=%v", st.BurnRatio, st.BudgetRemainingPct)
	}

	// 5) Partial coverage is measured but NAMED (1 of 2 reporting).
	st = cloud.MeasureSLO(ctx, slo, idx, func(context.Context, string) map[string]float64 {
		return map[string]float64{"i-1": 0}
	})
	if !st.Measurable || st.ResourcesReporting != 1 || st.ResourcesTotal != 2 {
		t.Fatalf("partial coverage: %+v", st)
	}
}

func TestCloudSLOHandlerContract(t *testing.T) {
	srv, s := newTestServerState(t)
	s.cloud = newCloudStore()
	s.cloudSLOs = newCloudSLOStore("") // in-memory
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st, b := do(t, srv, "POST", "/api/onboard", admin, map[string]any{
		"org_name": "Slo Corp", "tenant_name": "Slo Prod", "tenant_slug": "slo-prod",
	})
	if st != 201 {
		t.Fatalf("onboard: %d %s", st, b)
	}
	var ob onboardResponse
	if err := json.Unmarshal(b, &ob); err != nil {
		t.Fatal(err)
	}
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "sloadmin", "password": "Passw0rd!2345", "role": "admin", "tenant_id": ob.Tenant.ID,
	}); st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	tok := login(t, srv, "sloadmin", "Passw0rd!2345").Token

	// Empty list first.
	st, b = do(t, srv, "GET", "/api/cloud/slos", tok, nil)
	if st != 200 {
		t.Fatalf("GET empty: %d %s", st, b)
	}

	// Invalid PUT → 400.
	if st, _ := do(t, srv, "PUT", "/api/cloud/slos", tok, map[string]any{
		"slos": []map[string]any{{"app_name": "shop", "target_pct": 100.0, "window_days": 7}},
	}); st != 400 {
		t.Fatalf("target 100 must be refused, got %d", st)
	}

	// Valid PUT persists; tenant stamped from principal (no tenant in body).
	st, b = do(t, srv, "PUT", "/api/cloud/slos", tok, map[string]any{
		"slos": []map[string]any{{"app_name": "shop", "target_pct": 99.9, "window_days": 7}},
	})
	if st != 200 {
		t.Fatalf("PUT: %d %s", st, b)
	}
	var resp struct {
		TenantID string `json:"tenant_id"`
		SLOs     []struct {
			AppName string          `json:"app_name"`
			Status  *cloudSLOStatus `json:"status"`
		} `json:"slos"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TenantID != ob.Tenant.ID || len(resp.SLOs) != 1 || resp.SLOs[0].AppName != "shop" {
		t.Fatalf("wrong state: %+v", resp)
	}
	// No inventory + no metric lane in this harness → honest not-measurable.
	if resp.SLOs[0].Status == nil || resp.SLOs[0].Status.Measurable {
		t.Fatalf("no-data SLO must be not measurable: %+v", resp.SLOs[0].Status)
	}

	// Reset clears.
	if st, _ := do(t, srv, "PUT", "/api/cloud/slos", tok, map[string]any{"reset": true}); st != 200 {
		t.Fatal("reset failed")
	}
	st, b = do(t, srv, "GET", "/api/cloud/slos", tok, nil)
	if st != 200 {
		t.Fatal("GET after reset failed")
	}
	var after struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(b, &after); err != nil {
		t.Fatal(err)
	}
	if after.Count != 0 {
		t.Fatalf("reset must clear, count=%d", after.Count)
	}
}
