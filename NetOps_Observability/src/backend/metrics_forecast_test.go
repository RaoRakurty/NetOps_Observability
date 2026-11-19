// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"testing"

	"netops/backend/internal/flowquery"
)

func TestForecastRank(t *testing.T) {
	sat := forecastRow{Status: "saturated"}
	soon := forecastRow{Status: "trending", DaysTo90: 5}
	later := forecastRow{Status: "trending", DaysTo90: 30}
	unsteady := forecastRow{Status: "unsteady"}
	stable := forecastRow{Status: "stable"}
	building := forecastRow{Status: "building_baseline"}
	order := []forecastRow{sat, soon, later, unsteady, stable, building}
	for i := 1; i < len(order); i++ {
		if !(forecastRank(order[i-1]) < forecastRank(order[i])) {
			t.Errorf("rank order wrong at %s(%v) vs %s(%v)", order[i-1].Status, forecastRank(order[i-1]), order[i].Status, forecastRank(order[i]))
		}
	}
}

// Tracker 407: the Overview forecast is the Capacity tab's fit, projected onto
// the panel's unchanged response shape. "current" is the FITTED last day, so a
// single noisy day cannot move the date, and the two screens agree.
func TestForecastRowOfIsTheCapacityFit(t *testing.T) {
	speed := 100e6
	p95 := 70.0
	// 14 days rising 50 → 63 %, plus one wild last day: the fit, not the raw
	// last point, is "current".
	var pts [][2]float64
	for i := 0; i < 14; i++ {
		pts = append(pts, [2]float64{float64(i), 50 + float64(i)})
	}
	pts = append(pts, [2]float64{14, 89})
	fit := flowquery.FitForecast(pts)
	row := forecastRowOf(flowquery.CapacityRow{DeviceID: "dev-a", IfIndex: "1", IfName: "Gi0/1", SpeedBps: &speed, P95Pct: &p95, Forecast: fit})
	if row.Status != "trending" || fit.DaysTo90 == nil || row.DaysTo90 != *fit.DaysTo90 {
		t.Fatalf("row = %+v, fit = %+v; want trending with the fit's date", row, fit)
	}
	if row.CurrentUtil != *fit.FittedPct || row.CurrentUtil >= 89 {
		t.Errorf("current = %v, want the fitted %v (not the raw 89)", row.CurrentUtil, *fit.FittedPct)
	}
	if row.SlopePerDay != *fit.SlopePctPerDay || row.HistoryDays != 15 || row.Device != "dev-a" || row.Interface != "Gi0/1" {
		t.Errorf("row = %+v", row)
	}

	cases := []struct {
		fit        flowquery.Forecast
		status     string
		daysTo90   float64
		currentPct float64
	}{
		{flowquery.FitForecast(flat(14, 95)), "saturated", 0, 95},
		{flowquery.FitForecast(flat(14, 40)), "stable", -1, 40},
		{flowquery.FitForecast(zigzag(14)), "unsteady", -1, -1},
		{flowquery.FitForecast(flat(5, 40)), "building_baseline", -1, 70}, // no fit: the 24 h p95
		{flowquery.Forecast{Status: flowquery.ForecastSpeedUnknown}, "building_baseline", -1, 70},
	}
	for _, c := range cases {
		r := forecastRowOf(flowquery.CapacityRow{DeviceID: "d", IfIndex: "7", SpeedBps: &speed, P95Pct: &p95, Forecast: c.fit})
		if r.Status != c.status || r.DaysTo90 != c.daysTo90 {
			t.Errorf("%s: got %s / %v, want %s / %v", c.fit.Status, r.Status, r.DaysTo90, c.status, c.daysTo90)
		}
		if c.currentPct >= 0 && r.CurrentUtil != c.currentPct {
			t.Errorf("%s: current = %v, want %v", c.fit.Status, r.CurrentUtil, c.currentPct)
		}
		if r.Interface != "7" {
			t.Errorf("an interface with no name is shown by its index, got %q", r.Interface)
		}
	}
}

func flat(n int, v float64) [][2]float64 {
	pts := make([][2]float64, n)
	for i := range pts {
		pts[i] = [2]float64{float64(i), v}
	}
	return pts
}

// zigzag rises slowly under heavy noise: slope > 0, R² well under 0.5.
func zigzag(n int) [][2]float64 {
	pts := make([][2]float64, n)
	for i := range pts {
		v := 40 + 0.3*float64(i)
		if i%2 == 0 {
			v += 15
		}
		pts[i] = [2]float64{float64(i), v}
	}
	return pts
}
