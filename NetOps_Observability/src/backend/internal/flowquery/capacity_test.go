// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"testing"
)

func ramp(n int, start, step float64) [][2]float64 {
	pts := make([][2]float64, n)
	for i := range pts {
		pts[i] = [2]float64{float64(i), start + float64(i)*step}
	}
	return pts
}

func TestFitForecastRamp(t *testing.T) {
	// 50 %, 51 %, … 63 % over 14 days: slope 1 %/day, fitted 63 %, 27 days to 90 %.
	f := FitForecast(ramp(14, 50, 1))
	if f.Status != ForecastRising || *f.DaysTo90 != 27 || *f.SlopePctPerDay != 1 || *f.FittedPct != 63 || *f.R2 != 1 || f.HistoryDays != 14 {
		t.Fatalf("ramp forecast = %+v (days %v slope %v fitted %v r2 %v)", f, *f.DaysTo90, *f.SlopePctPerDay, *f.FittedPct, *f.R2)
	}
	if f := FitForecast(ramp(13, 50, 1)); f.Status != ForecastNotEnough || f.DaysTo90 != nil || f.HistoryDays != 13 || f.MinDays != 14 {
		t.Fatalf("13 days = %+v", f)
	}
}

func TestFitForecastStatuses(t *testing.T) {
	if f := FitForecast(ramp(14, 95, 0.1)); f.Status != ForecastAtOrOver || *f.DaysTo90 != 0 {
		t.Errorf("already over: %+v", f)
	}
	if f := FitForecast(ramp(14, 60, -1)); f.Status != ForecastFlat || f.DaysTo90 != nil {
		t.Errorf("falling: %+v", f)
	}
	if f := FitForecast(ramp(20, 40, 0)); f.Status != ForecastFlat || *f.R2 != 1 {
		t.Errorf("constant: %+v", f)
	}
	// 0.01 %/day from 10 %: 8000 days out → not rising.
	if f := FitForecast(ramp(14, 10, 0.01)); f.Status != ForecastFlat {
		t.Errorf("a crossing years away: %+v", f)
	}
	// A noisy series with a slight upward slope: R² well below 0.5.
	noisy := [][2]float64{}
	for i, v := range []float64{30, 70, 20, 80, 25, 75, 30, 72, 28, 79, 31, 74, 33, 80} {
		noisy = append(noisy, [2]float64{float64(i), v})
	}
	if f := FitForecast(noisy); f.Status != ForecastUnsteady || f.DaysTo90 != nil || *f.R2 >= ForecastMinR2 {
		t.Errorf("noisy: %+v r2=%v", f, *f.R2)
	}
}

func fp(v float64) *float64 { return &v }

func TestBuildCapacityRow(t *testing.T) {
	// A 100 Mb/s link with a known p95 of 40 Mb/s out, 25 in; peak 70.
	r := BuildCapacityRow(IfFigures{
		Key:   IfKey{Device: "edge-1", Index: "3", IfName: "Gi0/0/1"},
		P95In: fp(25e6), P95Out: fp(40e6), PeakIn: fp(30e6), PeakOut: fp(70e6), Speed: fp(100e6),
	})
	if r.SpeedBasis != SpeedReported || *r.P95Pct != 40 || *r.P95InPct != 25 || *r.P95OutPct != 40 || *r.PeakPct != 70 {
		t.Fatalf("row = %+v", r)
	}
	if *r.P95Bps != 40e6 || *r.HeadroomBps != 60e6 || *r.HeadroomPct != 60 || r.Forecast.Status != ForecastNotEnough {
		t.Fatalf("headroom = %v %v, forecast %+v", *r.HeadroomBps, *r.HeadroomPct, r.Forecast)
	}
	// No speed: throughput kept, every percentage, headroom and forecast absent.
	ns := BuildCapacityRow(IfFigures{Key: IfKey{Device: "edge-1", IfName: "ge0/1"}, P95In: fp(5e6)})
	if ns.SpeedBasis != SpeedUnknown || ns.P95Pct != nil || ns.HeadroomBps != nil || *ns.P95Bps != 5e6 || ns.Forecast.Status != ForecastSpeedUnknown {
		t.Fatalf("no speed = %+v", ns)
	}
	// A rate above twice the speed: the speed is wrong, so no percentage.
	im := BuildCapacityRow(IfFigures{Key: IfKey{Device: "e", Index: "1"}, P95In: fp(300e6), Speed: fp(100e6)})
	if im.SpeedBasis != SpeedImplausible || im.P95Pct != nil || im.Forecast.Status != ForecastSpeedUnknown {
		t.Fatalf("implausible = %+v", im)
	}
	// Over the speed but plausible: headroom clamps at 0.
	ov := BuildCapacityRow(IfFigures{Key: IfKey{Device: "e", Index: "1"}, P95In: fp(110e6), Speed: fp(100e6)})
	if *ov.HeadroomBps != 0 || *ov.HeadroomPct != 0 || *ov.P95Pct != 110 {
		t.Fatalf("over speed = %+v", ov)
	}
}

func TestDailyUtilBusierDirectionPerDay(t *testing.T) {
	day := int64(86400)
	in := map[int64]float64{day: 10e6, 2 * day: 20e6, 3 * day: 30e6}
	out := map[int64]float64{day: 15e6, 3 * day: 5e6, 4 * day: 40e6}
	pts := DailyUtil(in, out, 100e6)
	want := [][2]float64{{0, 15}, {1, 20}, {2, 30}, {3, 40}}
	if len(pts) != len(want) {
		t.Fatalf("points = %v", pts)
	}
	for i := range want {
		if pts[i] != want[i] {
			t.Fatalf("points = %v, want %v", pts, want)
		}
	}
	if DailyUtil(in, out, 0) != nil {
		t.Fatal("no speed, no utilisation")
	}
}

func TestCapacityQueries(t *testing.T) {
	if got, want := P95BpsQuery("in", 3600, 0), "quantile_over_time(0.95, (rate(device_if_in_octets[5m]) * 8)[3600s:5m])"; got != want {
		t.Errorf("p95 = %s", got)
	}
	if got, want := P95BpsQuery("in", 3600, 1794549600), "quantile_over_time(0.95, (rate(device_if_in_octets[5m]) * 8)[3600s:5m] @ 1794549600)"; got != want {
		t.Errorf("p95 at a past end = %s", got)
	}
	if got, want := PeakBpsQuery("out", 60, 0), "max_over_time((rate(device_if_out_octets[5m]) * 8)[300s:5m])"; got != want {
		t.Errorf("peak = %s", got)
	}
	if got, want := SpeedBpsQuery(0), "(device_if_speed > 0) * 1000000"; got != want {
		t.Errorf("speed = %s", got)
	}
	if got, want := SpeedBpsQuery(1794549600), "(last_over_time(device_if_speed[1h] @ 1794549600) > 0) * 1000000"; got != want {
		t.Errorf("speed at a past end = %s", got)
	}
	if got, want := DailyP95Query("in", []string{"edge.1", "edge-2", `x"}or{y`, "edge.1"}), `quantile_over_time(0.95, (rate(device_if_in_octets{device=~"edge-2|edge\\.1|xory"}[5m]) * 8)[1d:5m])`; got != want {
		t.Errorf("daily = %s", got)
	}
	if DailyP95Query("in", nil) != "" || DeviceSelector([]string{"", "\"}"}) != "" {
		t.Error("no ids must give no query (never a fleet-wide one)")
	}
}

func TestKeyOfAndSort(t *testing.T) {
	if k, ok := KeyOf(map[string]string{"device": "d", "index": "3"}); !ok || k.String() != "d|3" {
		t.Errorf("index key = %v %v", k, ok)
	}
	if k, ok := KeyOf(map[string]string{"device": "d", "ifName": " ge0/1 "}); !ok || k.String() != "d|name:ge0/1" {
		t.Errorf("name key = %v %v", k, ok)
	}
	if _, ok := KeyOf(map[string]string{"device": "d"}); ok {
		t.Error("no interface identity must not key")
	}
	rows := []CapacityRow{
		{DeviceID: "b", IfIndex: "1", P95Bps: fp(5)},
		{DeviceID: "a", IfIndex: "1", P95Pct: fp(40), P95Bps: fp(1)},
		{DeviceID: "a", IfIndex: "2", P95Pct: fp(80), P95Bps: fp(1)},
		{DeviceID: "c", IfIndex: "1", P95Bps: fp(9)},
	}
	SortCapacity(rows)
	if rows[0].IfIndex != "2" || rows[1].P95Pct == nil || rows[2].DeviceID != "c" || rows[3].DeviceID != "b" {
		t.Errorf("order = %+v", rows)
	}
}
