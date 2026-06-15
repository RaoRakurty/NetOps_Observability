package main

import (
	"math"
	"testing"
)

func TestLinFit(t *testing.T) {
	// y = 2x + 1
	pts := [][2]float64{{0, 1}, {1, 3}, {2, 5}, {3, 7}}
	slope, last, ok := linFit(pts)
	if !ok || math.Abs(slope-2) > 1e-9 || math.Abs(last-7) > 1e-9 {
		t.Fatalf("linFit slope=%.4f last=%.4f ok=%v, want 2/7/true", slope, last, ok)
	}
	if _, _, ok := linFit([][2]float64{{0, 1}}); ok {
		t.Error("single point should not fit")
	}
}

func TestDaysToThreshold(t *testing.T) {
	// 0.5 now, +0.01/day → (0.90-0.50)/0.01 = 40 days
	if d := daysToThreshold(0.90, 0.50, 0.01); math.Abs(d-40) > 1e-9 {
		t.Errorf("days=%.2f, want 40", d)
	}
	// flat → not trending up
	if d := daysToThreshold(0.90, 0.50, 0); d != -1 {
		t.Errorf("flat slope should be -1 (stable), got %.2f", d)
	}
	// declining → stable
	if d := daysToThreshold(0.90, 0.50, -0.02); d != -1 {
		t.Errorf("declining should be -1 (stable), got %.2f", d)
	}
	// already over → 0
	if d := daysToThreshold(0.90, 0.95, 0.01); d != 0 {
		t.Errorf("already saturated should be 0, got %.2f", d)
	}
}

func TestForecastRank(t *testing.T) {
	sat := forecastRow{Status: "saturated"}
	soon := forecastRow{Status: "trending", DaysTo90: 5}
	later := forecastRow{Status: "trending", DaysTo90: 30}
	stable := forecastRow{Status: "stable"}
	building := forecastRow{Status: "building_baseline"}
	if !(forecastRank(sat) < forecastRank(soon) && forecastRank(soon) < forecastRank(later) &&
		forecastRank(later) < forecastRank(stable) && forecastRank(stable) < forecastRank(building)) {
		t.Errorf("rank order wrong: sat=%.1f soon=%.1f later=%.1f stable=%.1f building=%.1f",
			forecastRank(sat), forecastRank(soon), forecastRank(later), forecastRank(stable), forecastRank(building))
	}
}
